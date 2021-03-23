//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;

namespace MultiFactor.Radius.Adapter.Server
{
    /// <summary>
    /// Main processor
    /// </summary>
    public class RadiusRouter
    {
        private Configuration _configuration;
        private ILogger _logger;
        private IRadiusPacketParser _packetParser;
        private ActiveDirectoryService _activeDirectoryService;
        private MultiFactorApiClient _multifactorApiClient;
        public event EventHandler<PendingRequest> RequestProcessed;
        private readonly ConcurrentDictionary<string, PendingRequest> _stateChallengePendingRequests = new ConcurrentDictionary<string, PendingRequest>();

        public RadiusRouter(Configuration configuration, IRadiusPacketParser packetParser, ILogger logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _packetParser = packetParser ?? throw new ArgumentNullException(nameof(packetParser));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _activeDirectoryService = new ActiveDirectoryService(configuration, logger);
            _multifactorApiClient = new MultiFactorApiClient(configuration, logger);
        }

        public void HandleRequest(PendingRequest request)
        {
            try
            {
                if (request.RequestPacket.Code != PacketCode.AccessRequest)
                {
                    _logger.Warning($"Unprocessable packet type: {request.RequestPacket.Code}");
                    return;
                }

                if (request.RequestPacket.Attributes.ContainsKey("State")) //Access-Challenge response 
                {
                    var receivedState = request.RequestPacket.GetString("State");

                    if (_stateChallengePendingRequests.ContainsKey(receivedState))
                    {
                        //second request with Multifactor challenge
                        request.ResponseCode = ProcessChallenge(request, receivedState);
                        request.State = receivedState;  //state for Access-Challenge message if otp is wrong (3 times allowed)

                        RequestProcessed?.Invoke(this, request);
                        return; //stop authentication process after otp code verification
                    }
                }

                var firstFactorAuthenticationResultCode = ProcessFirstAuthenticationFactor(request);
                if (firstFactorAuthenticationResultCode != PacketCode.AccessAccept)
                {
                    //first factor authentication rejected
                    request.ResponseCode = firstFactorAuthenticationResultCode;
                    RequestProcessed?.Invoke(this, request);

                    //stop authencation process
                    return;
                }

                if (request.Bypass2Fa)
                {
                    //second factor not trquired
                    var userName = request.RequestPacket.UserName;
                    _logger.Information($"Bypass second factor for user {userName}");

                    request.ResponseCode = PacketCode.AccessAccept;
                    RequestProcessed?.Invoke(this, request);

                    //stop authencation process
                    return;
                }

                var secondFactorAuthenticationResultCode = ProcessSecondAuthenticationFactor(request);

                request.ResponseCode = secondFactorAuthenticationResultCode;

                if (request.ResponseCode == PacketCode.AccessChallenge)
                {
                    AddStateChallengePendingRequest(request.State, request);
                }

                RequestProcessed?.Invoke(this, request);

            }
            catch(Exception ex)
            {
                _logger.Error(ex, "HandleRequest");
            }
        }

        private PacketCode ProcessFirstAuthenticationFactor(PendingRequest request)
        {
            switch(_configuration.FirstFactorAuthenticationSource)
            {
                case AuthenticationSource.ActiveDirectory:  //AD auth
                    return ProcessActiveDirectoryAuthentication(request);
                case AuthenticationSource.Radius:           //RADIUS auth
                    var radiusResponse = ProcessRadiusAuthentication(request);
                    if (radiusResponse == PacketCode.AccessAccept)
                    {
                        if (_configuration.CheckMembership)     //check membership without AD authentication
                        {
                            return ProcessActiveDirectoryMembership(request);
                        }
                    }
                    return radiusResponse;
                case AuthenticationSource.None:
                    if (_configuration.CheckMembership)     //check membership without AD authentication
                    {
                        return ProcessActiveDirectoryMembership(request);
                    }
                    return PacketCode.AccessAccept;         //first factor not required
                default:                                    //unknown source
                    throw new NotImplementedException(_configuration.FirstFactorAuthenticationSource.ToString());
            }
        }

        /// <summary>
        /// Authenticate request at Active Directory Domain with user-name and password
        /// </summary>
        private PacketCode ProcessActiveDirectoryAuthentication(PendingRequest request)
        {
            var userName = request.RequestPacket.UserName;
            var password = request.RequestPacket.UserPassword;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            if (string.IsNullOrEmpty(password))
            {
                _logger.Warning($"Can't find User-Password in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            var isValid = _activeDirectoryService.VerifyCredentialAndMembership(userName, password, request);

            return isValid ? PacketCode.AccessAccept : PacketCode.AccessReject;
        }

        /// <summary>
        /// Validate user membership within Active Directory Domain withoout password authentication
        /// </summary>
        private PacketCode ProcessActiveDirectoryMembership(PendingRequest request)
        {
            var userName = request.RequestPacket.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            var isValid = _activeDirectoryService.VerifyMembership(userName, request);

            return isValid ? PacketCode.AccessAccept : PacketCode.AccessReject;
        }

        /// <summary>
        /// Authenticate request at Network Policy Server with user-name and password
        /// </summary>
        private PacketCode ProcessRadiusAuthentication(PendingRequest request)
        {
            try
            {
                //sending request as is to Network Policy Server
                using (var client = new RadiusClient(_configuration.ServiceClientEndpoint, _logger))
                {
                    _logger.Debug($"Sending Access-Request message with Id={request.RequestPacket.Identifier} to Network Policy Server {_configuration.NpsServerEndpoint}");

                    var requestBytes = _packetParser.GetBytes(request.RequestPacket);
                    var response = client.SendPacketAsync(request.RequestPacket.Identifier, requestBytes, _configuration.NpsServerEndpoint, TimeSpan.FromSeconds(5)).Result;

                    if (response != null)
                    {
                        var responsePacket = _packetParser.Parse(response, request.RequestPacket.SharedSecret, request.RequestPacket.Authenticator);
                        _logger.Debug($"Received {responsePacket.Code} message with Id={responsePacket.Identifier} from Network Policy Server");
                        
                        if (responsePacket.Code == PacketCode.AccessAccept)
                        {
                            var userName = request.RequestPacket.UserName;
                            _logger.Information($"User '{userName}' credential and status verified successfully at {_configuration.NpsServerEndpoint}");
                        }

                        request.ResponsePacket = responsePacket;
                        return responsePacket.Code; //Code received from NPS
                    }
                    else
                    {
                        _logger.Warning($"Network Policy Server did not respond on message with Id={request.RequestPacket.Identifier}");
                        return PacketCode.AccessReject; //reject by default
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Radius authentication error");
            }
            
            return PacketCode.AccessReject; //reject by default
        }

        /// <summary>
        /// Authenticate request at MultiFactor with user-name only
        /// </summary>
        private PacketCode ProcessSecondAuthenticationFactor(PendingRequest request)
        {
            var userName = request.RequestPacket.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            //var response = _multifactorApiClient.CreateSecondFactorRequest(remoteHost, userName, userPassword, request.DisplayName, request.EmailAddress, request.UserPhone, out var multifactorStateId);
            var response = _multifactorApiClient.CreateSecondFactorRequest(request);
            //state = multifactorStateId;

            return response;
        }

        /// <summary>
        /// Verify one time password from user input
        /// </summary>
        private PacketCode ProcessChallenge(PendingRequest request, string state)
        {
            var userName = request.RequestPacket.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            PacketCode response;
            string userAnswer;

            switch (request.RequestPacket.AuthenticationType)
            {
                case AuthenticationType.PAP:
                    //user-password attribute holds second request challenge from user
                    userAnswer = request.RequestPacket.GetString("User-Password");

                    if (string.IsNullOrEmpty(userAnswer))
                    {
                        _logger.Warning($"Can't find User-Password with user response in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                        return PacketCode.AccessReject;
                    }
                    
                    break;
                case AuthenticationType.MSCHAP2:
                    var msChapResponse = request.RequestPacket.GetAttribute<byte[]>("MS-CHAP2-Response");

                    if (msChapResponse == null)
                    {
                        _logger.Warning($"Can't find MS-CHAP2-Response in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                        return PacketCode.AccessReject;
                    }

                    //forti behaviour
                    var otpData = msChapResponse.Skip(2).Take(6).ToArray();
                    userAnswer = Encoding.ASCII.GetString(otpData);

                    break;
                default:
                    _logger.Warning($"Unable to process {request.RequestPacket.AuthenticationType} challange in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                    return PacketCode.AccessReject;
            }

            response = _multifactorApiClient.Challenge(request, userName, userAnswer, state);

            switch (response)
            {
                case PacketCode.AccessAccept:
                    var stateChallengePendingRequest = GetStateChallengeRequest(state);
                    if (stateChallengePendingRequest != null)
                    {
                        request.UserGroups = stateChallengePendingRequest.UserGroups;
                        request.ResponsePacket = stateChallengePendingRequest.ResponsePacket;
                    }
                    break;
                case PacketCode.AccessReject:
                    RemoveStateChallengeRequest(state);
                    break;
            }

            return response;
        }

        /// <summary>
        /// Add authenticated request to local cache for otp/challenge
        /// </summary>
        private void AddStateChallengePendingRequest(string state, PendingRequest request)
        {
            if (!_stateChallengePendingRequests.TryAdd(state, request))
            {
                _logger.Error($"Unable to cache request Id={request.RequestPacket.Identifier}");
            }
        }

        /// <summary>
        /// Get authenticated request from local cache for otp/challenge
        /// </summary>
        private PendingRequest GetStateChallengeRequest(string state)
        {
            if (_stateChallengePendingRequests.TryRemove(state, out PendingRequest request))
            {
                return request;
            }

            _logger.Error($"Unable to get cached request with state={state}");
            return null;
        }

        /// <summary>
        /// Remove authenticated request from local cache
        /// </summary>
        /// <param name="state"></param>
        private void RemoveStateChallengeRequest(string state)
        {
            _stateChallengePendingRequests.TryRemove(state, out PendingRequest _);
        }
    }
}