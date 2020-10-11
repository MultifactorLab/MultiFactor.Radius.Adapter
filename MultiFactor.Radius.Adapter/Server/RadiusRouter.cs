//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using Serilog;
using System;
using System.Net;
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
            if (request.RequestPacket.Code != PacketCode.AccessRequest)
            {
                _logger.Warning($"Unprocessable packet type: {request.RequestPacket.Code}");
                return;
            }

            if (request.RequestPacket.Attributes.ContainsKey("State")) //Access-Challenge response 
            {
                if (request.RequestPacket.Attributes.ContainsKey("User-Password")) //With OTP code
                {
                    //second request with state and one time password
                    var mulfactorRequestId = Encoding.ASCII.GetString(request.RequestPacket.GetAttribute<byte[]>("State"));
                    request.ResponseCode = VerifySecondFactorOtpCode(request, mulfactorRequestId);
                    request.State = mulfactorRequestId;  //state for Access-Challenge message if otp is wrong (3 times allowed)

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
                var userName = request.RequestPacket.GetAttribute<string>("User-Name");
                _logger.Information($"Bypass second factor for user {userName}");

                request.ResponseCode = PacketCode.AccessAccept;
                RequestProcessed?.Invoke(this, request);

                //stop authencation process
                return;
            }

            var secondFactorAuthenticationResultCode = ProcessSecondAuthenticationFactor(request, out var state);

            request.ResponseCode = secondFactorAuthenticationResultCode;
            request.State = state;  //state for Access-Challenge message

            RequestProcessed?.Invoke(this, request);
        }

        private PacketCode ProcessFirstAuthenticationFactor(PendingRequest request)
        {
            switch(_configuration.FirstFactorAuthenticationSource)
            {
                case AuthenticationSource.ActiveDirectory:  //AD auth
                    return ProcessActiveDirectoryAuthentication(request);
                case AuthenticationSource.Radius:           //RADIUS auth
                    return ProcessRadiusAuthentication(request);
                case AuthenticationSource.None:
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
            var userName = request.RequestPacket.GetAttribute<string>("User-Name");

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            //user-password attribute hold second request otp from user
            var password = request.RequestPacket.GetAttribute<string>("User-Password");

            if (string.IsNullOrEmpty(password))
            {
                _logger.Warning($"Can't find User-Password in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            var isValid = _activeDirectoryService.VerifyCredential(userName, password, request);

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
                            var userName = request.RequestPacket.GetAttribute<string>("User-Name");
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
        private PacketCode ProcessSecondAuthenticationFactor(PendingRequest request, out string state)
        {
            state = null;
            var userName = request.RequestPacket.GetAttribute<string>("User-Name");

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            var remoteHost = request.RequestPacket.GetAttribute<string>("MS-Client-Machine-Account-Name");
            remoteHost = remoteHost ?? request.RequestPacket.GetAttribute<string>("MS-RAS-Client-Name");

            var userPassword = request.RequestPacket.GetAttribute<string>("User-Password");

            var response = _multifactorApiClient.CreateSecondFactorRequest(remoteHost, userName, userPassword, request.EmailAddress, request.UserPhone, out var multifactorStateId);
            state = multifactorStateId;

            if (response == PacketCode.AccessAccept)
            {
                _logger.Information($"Second factor for user '{userName}' verifyed successfully");
            }

            return response;
        }

        /// <summary>
        /// Verify one time password from user input
        /// </summary>
        private PacketCode VerifySecondFactorOtpCode(PendingRequest request, string state)
        {
            var userName = request.RequestPacket.GetAttribute<string>("User-Name");

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            //user-password attribute hold second request otp from user
            var otpCode = request.RequestPacket.GetAttribute<string>("User-Password");

            if (string.IsNullOrEmpty(otpCode))
            {
                _logger.Warning($"Can't find User-Password with OTP code in message Id={request.RequestPacket.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            var response = _multifactorApiClient.VerifyOtpCode(userName, otpCode, state);

            if (response == PacketCode.AccessAccept)
            {
                _logger.Information($"Second factor for user '{userName}' verifyed successfully");
            }

            return response;
        }
    }
}