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
            if (request.Packet.Code != PacketCode.AccessRequest)
            {
                _logger.Warning($"Unprocessable packet type: {request.Packet.Code}");
                return;
            }

            if (request.Packet.Attributes.ContainsKey("State"))
            {
                //second request with state and one time password
                var mulfactorRequestId = Encoding.ASCII.GetString(request.Packet.GetAttribute<byte[]>("State"));
                request.ResponseCode = VerifySecondFactorOtpCode(request, mulfactorRequestId);
                request.State = mulfactorRequestId;  //state for Access-Challenge message if otp is wrong (3 times allowed)

                RequestProcessed?.Invoke(this, request);
                return; //stop authentication process after otp code verification
            }

            var firstFactorAuthenticationResultCode = ProcessFirstAuthenticationFactor(request);
            if (firstFactorAuthenticationResultCode != PacketCode.AccessAccept)
            {
                //first factor authentication rejected
                request.ResponseCode = PacketCode.AccessReject;
                RequestProcessed?.Invoke(this, request);

                //stop authencation process
                return; 
            }

            if (request.Bypass2Fa)
            {
                //second factor not trquired
                var userName = request.Packet.GetAttribute<string>("User-Name");
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
            var userName = request.Packet.GetAttribute<string>("User-Name");

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.Packet.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            //user-password attribute hold second request otp from user
            var password = request.Packet.GetAttribute<string>("User-Password");

            if (string.IsNullOrEmpty(password))
            {
                _logger.Warning($"Can't find User-Password in message Id={request.Packet.Identifier} from {request.RemoteEndpoint}");
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
            var originalRequest = request.Packet;

            var npsRequestPacket = new RadiusPacket(PacketCode.AccessRequest, originalRequest.Identifier, _configuration.MultiFactorSharedSecret);

            //copy all attributes but not Message-Authenticator
            foreach (var attr in originalRequest.Attributes)
            {
                if (attr.Key != "Message-Authenticator")
                {
                    npsRequestPacket.Attributes.Add(attr.Key, attr.Value);
                }
            }

            //add nas-id
            npsRequestPacket.AddAttribute("NAS-Identifier", _configuration.NasIdentifier);

            //sending request as is to Network Policy Server
            using (var client = new RadiusClient(_configuration.ServiceClientEndpoint, _packetParser, _logger))
            {
                _logger.Information($"Sending Access-Request message with Id={npsRequestPacket.Identifier} to Network Policy Server {_configuration.NpsServerEndpoint}");

                var response = client.SendPacketAsync(npsRequestPacket, _configuration.NpsServerEndpoint, TimeSpan.FromSeconds(5), request.OriginalUnpackedRequest).Result;

                if (response != null)
                {
                    _logger.Information($"Received {response.Code} message with Id={response.Identifier} from Network Policy Server");
                    return response.Code; //Code received from NPS
                }
                else
                {
                    _logger.Warning($"Network Policy Server did not respond on message with Id={npsRequestPacket.Identifier}");
                    return PacketCode.AccessReject; //reject by default
                }
            }
        }

        /// <summary>
        /// Authenticate request at MultiFactor with user-name only
        /// </summary>
        private PacketCode ProcessSecondAuthenticationFactor(PendingRequest request, out string state)
        {
            state = null;
            var userName = request.Packet.GetAttribute<string>("User-Name");

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.Packet.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            var remoteHost = request.Packet.GetAttribute<string>("MS-Client-Machine-Account-Name");
            var userPassword = request.Packet.GetAttribute<string>("User-Password");


            var response = _multifactorApiClient.CreateSecondFactorRequest(remoteHost, userName, userPassword, request.UserPhone, out var multifactorStateId);
            state = multifactorStateId;
            return response;
        }

        /// <summary>
        /// Verify one time password from user input
        /// </summary>
        private PacketCode VerifySecondFactorOtpCode(PendingRequest request, string state)
        {
            var userName = request.Packet.GetAttribute<string>("User-Name");

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning($"Can't find User-Name in message Id={request.Packet.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            //user-password attribute hold second request otp from user
            var otpCode = request.Packet.GetAttribute<string>("User-Password");

            if (string.IsNullOrEmpty(otpCode))
            {
                _logger.Warning($"Can't find User-Password with OTP code in message Id={request.Packet.Identifier} from {request.RemoteEndpoint}");
                return PacketCode.AccessReject;
            }

            var response = _multifactorApiClient.VerifyOtpCode(userName, otpCode, state);
            return response;
        }
    }
}
