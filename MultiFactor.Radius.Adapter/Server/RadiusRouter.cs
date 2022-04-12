//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services;
using MultiFactor.Radius.Adapter.Services.Ldap;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server
{
    /// <summary>
    /// Main processor
    /// </summary>
    public class RadiusRouter
    {
        private ServiceConfiguration _serviceConfiguration;
        private ILogger _logger;
        private IRadiusPacketParser _packetParser;
        private IDictionary<string, ActiveDirectoryService> _activeDirectoryServices;
        private MultiFactorApiClient _multifactorApiClient;
        public event EventHandler<PendingRequest> RequestProcessed;
        private readonly ConcurrentDictionary<string, PendingRequest> _stateChallengePendingRequests = new ConcurrentDictionary<string, PendingRequest>();
        private CacheService _cacheService;
        private PasswordChangeHandler _passwordChangeHandler;

        private DateTime _startedAt = DateTime.Now;

        public RadiusRouter(ServiceConfiguration serviceConfiguration, IRadiusPacketParser packetParser, CacheService cacheService, ILogger logger)
        {
            _serviceConfiguration = serviceConfiguration ?? throw new ArgumentNullException(nameof(serviceConfiguration));
            _packetParser = packetParser ?? throw new ArgumentNullException(nameof(packetParser));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _multifactorApiClient = new MultiFactorApiClient(serviceConfiguration, logger);

            //stanalone AD service instance for each domain/forest with cached schema
            _activeDirectoryServices = new Dictionary<string, ActiveDirectoryService>();
            var domains = _serviceConfiguration.GetAllActiveDirectoryDomains();
            foreach(var domain in domains)
            {
                _activeDirectoryServices.Add(domain, new ActiveDirectoryService(_logger, domain));
            }

            _passwordChangeHandler = new PasswordChangeHandler(_cacheService, _activeDirectoryServices);
        }

        public async Task HandleRequest(PendingRequest request, ClientConfiguration clientConfig)
        {
            try
            {
                if (request.RequestPacket.Code == PacketCode.StatusServer)
                {
                    //status
                    var uptime = (DateTime.Now - _startedAt);
                    request.ReplyMessage = $"Server up {uptime.Days} days {uptime.ToString("hh\\:mm\\:ss")}";
                    request.ResponseCode = PacketCode.AccessAccept;
                    RequestProcessed?.Invoke(this, request);
                    return;
                }

                if (request.RequestPacket.Code != PacketCode.AccessRequest)
                {
                    _logger.Warning("Unprocessable packet type: {code}", request.RequestPacket.Code);
                    return;
                }

                var passwordChangeStatusCode = _passwordChangeHandler.HandleRequest(request, clientConfig);
                if (passwordChangeStatusCode != PacketCode.AccessAccept)
                {
                    request.ResponseCode = passwordChangeStatusCode;
                    RequestProcessed?.Invoke(this, request);
                    return;
                }

                if (request.RequestPacket.State != null) //Access-Challenge response 
                {
                    var receivedState = request.RequestPacket.State;

                    if (_stateChallengePendingRequests.ContainsKey(receivedState))
                    {
                        //second request with Multifactor challenge
                        request.ResponseCode = await ProcessChallenge(request, clientConfig, receivedState);
                        request.State = receivedState;  //state for Access-Challenge message if otp is wrong (3 times allowed)

                        RequestProcessed?.Invoke(this, request);
                        return; //stop authentication process after otp code verification
                    }
                }

                var firstFactorAuthenticationResultCode = await ProcessFirstAuthenticationFactor(request, clientConfig);
                if (firstFactorAuthenticationResultCode != PacketCode.AccessAccept)
                {
                    //User password expired ot must be changed
                    if (request.MustChangePassword)
                    {
                        request.MustChangePassword = true;
                        request.ResponseCode = _passwordChangeHandler.HandleRequest(request, clientConfig);
                        RequestProcessed?.Invoke(this, request);
                        return;
                    }

                    //first factor authentication rejected
                    request.ResponseCode = firstFactorAuthenticationResultCode;
                    RequestProcessed?.Invoke(this, request);

                    //stop authencation process
                    return;
                }

                if (request.Bypass2Fa)
                {
                    //second factor not required
                    var userName = request.RequestPacket.UserName;
                    _logger.Information("Bypass second factor for user '{user:l}'", userName);

                    request.ResponseCode = PacketCode.AccessAccept;
                    RequestProcessed?.Invoke(this, request);

                    //stop authencation process
                    return;
                }

                var secondFactorAuthenticationResultCode = await ProcessSecondAuthenticationFactor(request, clientConfig);

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

        private async Task<PacketCode> ProcessFirstAuthenticationFactor(PendingRequest request, ClientConfiguration clientConfig)
        {
            switch(clientConfig.FirstFactorAuthenticationSource)
            {
                case AuthenticationSource.ActiveDirectory:  //AD auth
                    return ProcessActiveDirectoryAuthentication(request, clientConfig);
                case AuthenticationSource.AdLds:            //AD LDS internal auth
                    return ProcessLdapAuthentication(request, clientConfig);
                case AuthenticationSource.Radius:           //RADIUS auth
                    var radiusResponse = await ProcessRadiusAuthentication(request, clientConfig);
                    if (radiusResponse == PacketCode.AccessAccept)
                    {
                        if (clientConfig.CheckMembership)     //check membership without AD authentication
                        {
                            return ProcessActiveDirectoryMembership(request, clientConfig);
                        }
                    }
                    return radiusResponse;
                case AuthenticationSource.None:
                    if (clientConfig.CheckMembership)     //check membership without AD authentication
                    {
                        return ProcessActiveDirectoryMembership(request, clientConfig);
                    }
                    return PacketCode.AccessAccept;         //first factor not required
                default:                                    //unknown source
                    throw new NotImplementedException(clientConfig.FirstFactorAuthenticationSource.ToString());
            }
        }

        /// <summary>
        /// Authenticate request at Active Directory Domain with user-name and password
        /// </summary>
        private PacketCode ProcessActiveDirectoryAuthentication(PendingRequest request, ClientConfiguration clientConfig)
        {
            var userName = request.RequestPacket.UserName;
            var password = request.RequestPacket.UserPassword;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            if (string.IsNullOrEmpty(password))
            {
                _logger.Warning("Can't find User-Password in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            //trying to authenticate for each domain/forest
            var domains = clientConfig.ActiveDirectoryDomain.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var domain in domains)
            {
                var activeDirectoryService = _activeDirectoryServices[domain.Trim()];
                var isValid = activeDirectoryService.VerifyCredentialAndMembership(clientConfig, userName, password, request);
                if (isValid)
                {
                    return PacketCode.AccessAccept;
                }

                if (request.MustChangePassword)
                {
                    request.MustChangePasswordDomain = domain;
                    return PacketCode.AccessReject;
                }
            }

            return PacketCode.AccessReject;
        }

        /// <summary>
        /// Authenticate request at LDAP with user-name and password
        /// </summary>
        private PacketCode ProcessLdapAuthentication(PendingRequest request, ClientConfiguration clientConfig)
        {
            var userName = request.RequestPacket.UserName;
            var password = request.RequestPacket.UserPassword;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            if (string.IsNullOrEmpty(password))
            {
                _logger.Warning("Can't find User-Password in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            var ldapService = new AdLdsService(_logger);
            var isValid = ldapService.VerifyCredentialAndMembership(userName, password, clientConfig);
            return isValid ? PacketCode.AccessAccept : PacketCode.AccessReject;
        }

        /// <summary>
        /// Validate user membership within Active Directory Domain withoout password authentication
        /// </summary>
        private PacketCode ProcessActiveDirectoryMembership(PendingRequest request, ClientConfiguration clientConfig)
        {
            var userName = request.RequestPacket.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            //trying to authenticate for each domain/forest
            var domains = clientConfig.ActiveDirectoryDomain.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var domain in domains)
            {
                var activeDirectoryService = _activeDirectoryServices[domain.Trim()];
                var isValid = activeDirectoryService.VerifyMembership(clientConfig, userName, request);
                if (isValid)
                {
                    return PacketCode.AccessAccept;
                }
            }

            return PacketCode.AccessReject;
        }

        /// <summary>
        /// Authenticate request at Remote Radius Server with user-name and password
        /// </summary>
        private async Task<PacketCode> ProcessRadiusAuthentication(PendingRequest request, ClientConfiguration clientConfig)
        {
            try
            {
                //sending request to Remote Radius Server
                using (var client = new RadiusClient(clientConfig.ServiceClientEndpoint, _logger))
                {
                    _logger.Debug($"Sending {{code:l}} message with id={{id}} to Remote Radius Server {clientConfig.NpsServerEndpoint}", request.RequestPacket.Code.ToString(), request.RequestPacket.Identifier);

                    var requestBytes = _packetParser.GetBytes(request.RequestPacket);
                    var response = await client.SendPacketAsync(request.RequestPacket.Identifier, requestBytes, clientConfig.NpsServerEndpoint, TimeSpan.FromSeconds(5));

                    if (response != null)
                    {
                        var responsePacket = _packetParser.Parse(response, request.RequestPacket.SharedSecret, request.RequestPacket.Authenticator);
                        _logger.Debug("Received {code:l} message with id={id} from Remote Radius Server", responsePacket.Code.ToString(), responsePacket.Identifier);

                        if (responsePacket.Code == PacketCode.AccessAccept)
                        {
                            var userName = request.RequestPacket.UserName;
                            _logger.Information($"User '{{user:l}}' credential and status verified successfully at {clientConfig.NpsServerEndpoint}", userName);
                        }

                        request.ResponsePacket = responsePacket;
                        return responsePacket.Code; //Code received from NPS
                    }
                    else
                    {
                        _logger.Warning("Remote Radius Server did not respond on message with id={id}", request.RequestPacket.Identifier);
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
        private async Task<PacketCode> ProcessSecondAuthenticationFactor(PendingRequest request, ClientConfiguration clientConfig)
        {
            var userName = request.RequestPacket.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            if (request.RequestPacket.IsVendorAclRequest == true)
            {
                //security check
                if (clientConfig.FirstFactorAuthenticationSource == AuthenticationSource.Radius)
                {
                    _logger.Information("Bypass second factor for user {user:l}", userName);
                    return PacketCode.AccessAccept;
                }
            }

            var response = await _multifactorApiClient.CreateSecondFactorRequest(request, clientConfig);

            return response;
        }

        /// <summary>
        /// Verify one time password from user input
        /// </summary>
        private async Task<PacketCode> ProcessChallenge(PendingRequest request, ClientConfiguration clientConfig, string state)
        {
            var userName = request.RequestPacket.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            PacketCode response;
            string userAnswer;

            switch (request.RequestPacket.AuthenticationType)
            {
                case AuthenticationType.PAP:
                    //user-password attribute holds second request challenge from user
                    userAnswer = request.RequestPacket.UserPassword;

                    if (string.IsNullOrEmpty(userAnswer))
                    {
                        _logger.Warning("Can't find User-Password with user response in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        return PacketCode.AccessReject;
                    }
                    
                    break;
                case AuthenticationType.MSCHAP2:
                    var msChapResponse = request.RequestPacket.GetAttribute<byte[]>("MS-CHAP2-Response");

                    if (msChapResponse == null)
                    {
                        _logger.Warning("Can't find MS-CHAP2-Response in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        return PacketCode.AccessReject;
                    }

                    //forti behaviour
                    var otpData = msChapResponse.Skip(2).Take(6).ToArray();
                    userAnswer = Encoding.ASCII.GetString(otpData);

                    break;
                default:
                    _logger.Warning("Unable to process {auth} challange in message id={id} from {host:l}:{port}", request.RequestPacket.AuthenticationType, request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                    return PacketCode.AccessReject;
            }

            response = await _multifactorApiClient.Challenge(request, clientConfig, userName, userAnswer, state);

            switch (response)
            {
                case PacketCode.AccessAccept:
                    var stateChallengePendingRequest = GetStateChallengeRequest(state);
                    if (stateChallengePendingRequest != null)
                    {
                        request.UserGroups = stateChallengePendingRequest.UserGroups;
                        request.ResponsePacket = stateChallengePendingRequest.ResponsePacket;
                        request.LdapAttrs = stateChallengePendingRequest.LdapAttrs;
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
                _logger.Error("Unable to cache request id={id}", request.RequestPacket.Identifier);
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