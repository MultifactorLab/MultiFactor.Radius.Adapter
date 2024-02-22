//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    public class DefaultFirstAuthFactorProcessor : IFirstAuthFactorProcessor
    {
        private readonly ActiveDirectoryMembershipVerifier _membershipVerifier;
        private readonly ForestMetadataCache _metadataCache;
        private readonly ILogger _logger;

        public DefaultFirstAuthFactorProcessor(ActiveDirectoryMembershipVerifier membershipVerifier, ForestMetadataCache metadataCache, ILogger logger)
        {
            _membershipVerifier = membershipVerifier ?? throw new ArgumentNullException(nameof(membershipVerifier));
            _metadataCache = metadataCache ?? throw new ArgumentNullException(nameof(metadataCache));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.None;

        public Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request)
        {
            if (!request.Configuration.CheckMembership)
            {
                if (request.Configuration.UseUpnAsIdentity)
                {
                    var attrs = LoadRequiredAttributes(request, request.Configuration, "userPrincipalName");
                    if (!attrs.ContainsKey("userPrincipalName"))
                    {
                        _logger.Warning("Attribute 'userPrincipalName' was not loaded");
                        return Task.FromResult(PacketCode.AccessReject);
                    }

                    request.Upn = attrs["userPrincipalName"].FirstOrDefault();
                }

                return Task.FromResult(PacketCode.AccessAccept);
            }

            // check membership without AD authentication
            var result = _membershipVerifier.VerifyMembership(request, request.Configuration);
            var handler = new MembershipVerificationResultHandler(result);

            handler.EnrichRequest(request);
            return Task.FromResult(handler.GetDecision());
        }

        private Dictionary<string, string[]> LoadRequiredAttributes(PendingRequest request, ClientConfiguration clientConfig, params string[] attrs)
        {
            var userName = request.UserName;
            if (string.IsNullOrEmpty(userName))
            {
                throw new Exception($"Can't find User-Name in message id={request.RequestPacket.Id.Identifier} from {request.RemoteEndpoint.Address}:{request.RemoteEndpoint.Port}");
            }

            var attributes = new Dictionary<string, string[]>();
            foreach (var domain in clientConfig.SplittedActiveDirectoryDomains)
            {
                if (attributes.Any()) break;

                var domainIdentity = LdapIdentity.FqdnToDn(domain);

                try
                {
                    var user = LdapIdentityFactory.CreateUserIdentity(clientConfig, userName);

                    _logger.Debug($"Loading attributes for user '{{user:l}}' at {domainIdentity}", user.Name);
                    using (var connection = CreateConnection(domain))
                    {
                        var schema = _metadataCache.Get(
                            clientConfig.Name,
                            domainIdentity,
                            () => new ForestSchemaLoader(clientConfig, connection, _logger).Load(domainIdentity));

                        attributes = new ProfileLoader(schema, _logger).LoadAttributes(connection, domainIdentity, user, attrs);
                    }
                }
                catch (UserDomainNotPermittedException ex)
                {
                    _logger.Warning(ex.Message);
                    continue;
                }
                catch (UserNameFormatException ex)
                {
                    _logger.Warning(ex.Message);
                    continue;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, $"Loading attributes of user '{{user:l}}' at {domainIdentity} failed", userName);
                    _logger.Information("Run MultiFactor.Raduis.Adapter as user with domain read permissions (basically any domain user)");
                    continue;
                }
            }

            return attributes;
        }

        private LdapConnection CreateConnection(string currentDomain)
        {
            var connection = new LdapConnection(currentDomain);
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.RootDseCache = true;
            connection.Bind();

            return connection;
        }
    }
}