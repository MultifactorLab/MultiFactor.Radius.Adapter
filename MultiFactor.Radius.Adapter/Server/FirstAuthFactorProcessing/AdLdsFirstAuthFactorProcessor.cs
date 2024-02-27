//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services.Ldap;
using Serilog;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    /// <summary>
    /// Authenticate request at LDAP with user-name and password
    /// </summary>
    public class AdLdsFirstAuthFactorProcessor : IFirstAuthFactorProcessor
    {
        private readonly AdLdsService _adlds;
        private readonly ILogger _logger;

        public AdLdsFirstAuthFactorProcessor(AdLdsService adlds, ILogger logger)
        {
            _adlds = adlds;
            _logger = logger;
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.AdLds;

        public Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request)
        {
            if (string.IsNullOrEmpty(request.UserName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return Task.FromResult(PacketCode.AccessReject);
            }

            if (string.IsNullOrEmpty(request.Passphrase.Password))
            {
                _logger.Warning("Can't find User-Password in message id={id} from {host:l}:{port}", request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return Task.FromResult(PacketCode.AccessReject);
            }

            var isValid = _adlds.VerifyCredentialAndMembership(request);
            return Task.FromResult(isValid ? PacketCode.AccessAccept : PacketCode.AccessReject);
        }
    }
}