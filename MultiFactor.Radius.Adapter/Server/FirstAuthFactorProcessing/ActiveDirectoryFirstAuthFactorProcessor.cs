//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    /// <summary>
    /// Authenticate request at Active Directory Domain with user-name and password
    /// </summary>
    public class ActiveDirectoryFirstAuthFactorProcessor : IFirstAuthFactorProcessor
    {
        private readonly IDictionary<string, ActiveDirectoryService> _activeDirectoryServices;
        private readonly ILogger _logger;

        public ActiveDirectoryFirstAuthFactorProcessor(IDictionary<string, ActiveDirectoryService> activeDirectoryServices,
            ILogger logger)
        {
            _activeDirectoryServices = activeDirectoryServices ?? throw new ArgumentNullException(nameof(activeDirectoryServices));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.ActiveDirectory;

        public Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request)
        {
            var userName = request.UserName;
            var password = request.RequestPacket.TryGetUserPassword();

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return Task.FromResult(PacketCode.AccessReject);
            }

            if (string.IsNullOrEmpty(password))
            {
                _logger.Warning("Can't find User-Password in message id={id} from {host:l}:{port}", request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return Task.FromResult(PacketCode.AccessReject);
            }

            //trying to authenticate for each domain/forest
            foreach (var domain in request.Configuration.SplittedActiveDirectoryDomains)
            {
                var activeDirectoryService = _activeDirectoryServices[domain.Trim()];
                var isValid = activeDirectoryService.VerifyCredentialAndMembership(request.Configuration, userName, password, request);
                if (isValid)
                {
                    return Task.FromResult(PacketCode.AccessAccept);
                }

                if (request.MustChangePassword)
                {
                    return Task.FromResult(PacketCode.AccessReject);
                }
            }

            return Task.FromResult(PacketCode.AccessReject);
        }
    }
}