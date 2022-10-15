//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services.Ldap;
using Serilog;
using System;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    /// <summary>
    /// Authenticate request at LDAP with user-name and password
    /// </summary>
    public class AdLdsFirstAuthFactorProcessor : IFirstAuthFactorProcessor
    {
        private readonly ILogger _logger;

        public AdLdsFirstAuthFactorProcessor(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.AdLds;

        public Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request, ClientConfiguration clientConfig)
        {
            var userName = request.UserName;
            var password = request.RequestPacket.TryGetUserPassword();

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return Task.FromResult(PacketCode.AccessReject);
            }

            if (string.IsNullOrEmpty(password))
            {
                _logger.Warning("Can't find User-Password in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return Task.FromResult(PacketCode.AccessReject);
            }

            var ldapService = new AdLdsService(_logger);
            var isValid = ldapService.VerifyCredentialAndMembership(userName, password, clientConfig);
            return Task.FromResult(isValid ? PacketCode.AccessAccept : PacketCode.AccessReject);
        }
    }
}