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
using System.Linq;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    public class AnonymousProcessor : IFirstAuthFactorProcessor
    {
        private readonly ActiveDirectoryMembershipVerifier _membershipVerifier;
        private readonly ForestMetadataCache _metadataCache;
        private readonly LdapConnectionFactory _connectionFactory;
        private readonly ILogger _logger;

        public AnonymousProcessor(ActiveDirectoryMembershipVerifier membershipVerifier, 
            ForestMetadataCache metadataCache,
            LdapConnectionFactory connectionFactory,
            ILogger logger)
        {
            _membershipVerifier = membershipVerifier ?? throw new ArgumentNullException(nameof(membershipVerifier));
            _metadataCache = metadataCache ?? throw new ArgumentNullException(nameof(metadataCache));
            _connectionFactory = connectionFactory;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.None;

        public Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request)
        {
            if (request.Configuration.CheckMembership)
            {
                // check membership without AD authentication
                var result = _membershipVerifier.VerifyMembership(request);
                var handler = new MembershipVerificationResultHandler(result);

                handler.EnrichRequest(request);
                return Task.FromResult(handler.GetDecision());
            }

            if (request.Configuration.UseIdentityAttribute)
            {
                var attrs = LoadRequiredAttributes(request, request.Configuration.TwoFAIdentityAttribyte);
                if (!attrs.ContainsKey(request.Configuration.TwoFAIdentityAttribyte))
                {
                    _logger.Warning("Attribute '{TwoFAIdentityAttribyte}' was not loaded", request.Configuration.TwoFAIdentityAttribyte);
                    return Task.FromResult(PacketCode.AccessReject);
                }

                var existedAttributes = new LdapAttributes(request.Profile.LdapAttrs);
                existedAttributes.Replace(request.Configuration.TwoFAIdentityAttribyte, new[] { attrs[request.Configuration.TwoFAIdentityAttribyte].FirstOrDefault() });
                request.Profile.UpdateAttributes(existedAttributes);
            }
            return Task.FromResult(PacketCode.AccessAccept);
        }

        private Dictionary<string, string[]> LoadRequiredAttributes(PendingRequest request, params string[] attrs)
        {
            if (string.IsNullOrEmpty(request.UserName))
            {
                throw new Exception($"Can't find User-Name in message id={request.RequestPacket.Header.Identifier} from {request.RemoteEndpoint.Address}:{request.RemoteEndpoint.Port}");
            }

            var attributes = new Dictionary<string, string[]>();
            foreach (var domain in request.Configuration.SplittedActiveDirectoryDomains)
            {
                if (attributes.Any()) break;

                var domainIdentity = LdapIdentity.FqdnToDn(domain);

                try
                {
                    var user = LdapIdentityFactory.CreateUserIdentity(request.Configuration, request.UserName);

                    _logger.Debug($"Loading attributes for user '{{user:l}}' at {domainIdentity}", user.Name);
                    using (var connection = _connectionFactory.CreateAsCurrentProcessUser(domain))
                    {
                        connection.Bind();
                        var schema = _metadataCache.Get(
                            request.Configuration.Name,
                            domainIdentity,
                            () => new ForestSchemaLoader(request.Configuration, connection, _logger).Load(domainIdentity));

                        attributes = new ProfileLoader(schema, _logger).LoadAttributes(connection, domainIdentity, user, attrs);
                    }
                }
                catch (UserDomainNotPermittedException ex)
                {
                    _logger.Warning(ex.Message);
                }
                catch (UserNameFormatException ex)
                {
                    _logger.Warning(ex.Message);
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, $"Loading attributes of user '{{user:l}}' at {domainIdentity} failed", request.UserName);
                    _logger.Information("Run MultiFactor.Raduis.Adapter as user with domain read permissions (basically any domain user)");
                }
            }

            return attributes;
        }
    }
}