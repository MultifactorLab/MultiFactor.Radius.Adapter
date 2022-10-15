//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using Serilog;
using System;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    /// <summary>
    /// Authenticate request at Remote Radius Server with user-name and password
    /// </summary>
    public class RadiusFirstAuthFactorProcessor : IFirstAuthFactorProcessor
    {
        private readonly IRadiusPacketParser _packetParser;
        private readonly ActiveDirectoryMembershipVerifier _membershipProcessor;
        private readonly ILogger _logger;

        public RadiusFirstAuthFactorProcessor(IRadiusPacketParser packetParser,
            ActiveDirectoryMembershipVerifier membershipProcessor,
            ILogger logger)
        {
            _packetParser = packetParser ?? throw new ArgumentNullException(nameof(packetParser));
            _membershipProcessor = membershipProcessor ?? throw new ArgumentNullException(nameof(membershipProcessor));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.Radius;

        public async Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request, ClientConfiguration clientConfig)
        {
            var radiusResponse = await ProcessRadiusAuthentication(request, clientConfig);
            if (radiusResponse != PacketCode.AccessAccept)
            {
                return radiusResponse;
            }

            if (!clientConfig.CheckMembership)     //check membership without AD authentication
            {
                return PacketCode.AccessAccept;
            }

            // check membership without AD authentication
            var result = _membershipProcessor.VerifyMembership(request, clientConfig);
            var handler = new MembershipVerificationResultHandler(result);

            handler.EnrichRequest(request);
            return handler.GetDecision();
        }

        public async Task<PacketCode> ProcessRadiusAuthentication(PendingRequest request, ClientConfiguration clientConfig)
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
                            var userName = request.UserName;
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
    }
}