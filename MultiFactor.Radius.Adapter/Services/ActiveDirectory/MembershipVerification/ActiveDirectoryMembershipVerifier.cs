//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    public class ActiveDirectoryMembershipVerifier
    {
        private readonly ILogger _logger;
        private readonly ForestMetadataCache _metadataCache;
        private readonly NetbiosService _netbiosService;
        private readonly LdapConnectionFactory _connectionFactory;

        public ActiveDirectoryMembershipVerifier(ILogger logger, 
            ForestMetadataCache metadataCache, 
            NetbiosService netbiosService,
            LdapConnectionFactory connectionFactory)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _metadataCache = metadataCache ?? throw new ArgumentNullException(nameof(metadataCache));
            _netbiosService = netbiosService;
            _connectionFactory = connectionFactory;
        }

        /// <summary>
        /// Validate user membership within Active Directory Domain without password authentication
        /// </summary>
        public ComplexMembershipVerificationResult VerifyMembership(PendingRequest request)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var result = new ComplexMembershipVerificationResult();

            if (string.IsNullOrEmpty(request.UserName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", 
                    request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return result;
            }

            LdapProfile profile = null;

            //trying to authenticate for each domain/forest
            foreach (var domain in request.Configuration.SplittedActiveDirectoryDomains)
            {
                var userDomain = domain;
                var domainIdentity = LdapIdentity.FqdnToDn(userDomain);
                try
                {
                    var user = LdapIdentityFactory.CreateUserIdentity(request.Configuration, request.UserName);
                    _logger.Debug("Verifying user '{User:l}' membership at {Domain:l}", user, domainIdentity);

                    if (user.HasNetbiosName())
                    {
                        user = _netbiosService.ConvertToUpnUser(request.Configuration, user, userDomain);
                        var suffix = user.UpnToSuffix();
                        if (!request.Configuration.IsPermittedDomain(suffix))
                        {
                            throw new UserDomainNotPermittedException($"User domain {suffix} not permitted");
                        }
                    }

                    using (var connection = _connectionFactory.CreateAsCurrentProcessUser(domain))
                    {
                        var schema = _metadataCache.Get(
                            request.Configuration.Name,
                            domainIdentity,
                            () => new ForestSchemaLoader(request.Configuration, connection, _logger).Load(domainIdentity));

                        if (profile == null)
                        {
                            profile = new ProfileLoader(schema, _logger)
                                .LoadProfile(request.Configuration, connection, domainIdentity, user);
                        }
                        if (profile == null)
                        {
                            result.AddDomainResult(MembershipVerificationResult.Create(domainIdentity)
                                .SetSuccess(false)
                                .Build());
                            continue;
                        }

                        var res = VerifyMembership(request.Configuration, profile, domainIdentity, user);
                        result.AddDomainResult(res);

                        if (res.IsSuccess) break;
                    }
                }
                catch (UserDomainNotPermittedException ex)
                {
                    _logger.Warning(ex.Message);
                    result.AddDomainResult(MembershipVerificationResult.Create(domainIdentity)
                        .SetSuccess(false)
                        .Build());
                    continue;
                }
                catch (UserNameFormatException ex)
                {
                    _logger.Warning(ex.Message);
                    result.AddDomainResult(MembershipVerificationResult.Create(domainIdentity)
                        .SetSuccess(false)
                        .Build());
                    continue;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Verification user '{User:l}' membership at {Domain:l} failed", request.UserName, domainIdentity);
                    _logger.Information("Run MultiFactor.Raduis.Adapter as user with domain read permissions (basically any domain user)");
                    result.AddDomainResult(MembershipVerificationResult.Create(domainIdentity)
                        .SetSuccess(false)
                        .Build());
                    continue;
                }
            }

            return result;
        }

        private MembershipVerificationResult VerifyMembership(ClientConfiguration clientConfig,
            LdapProfile profile,
            LdapIdentity domain,
            LdapIdentity user)
        {
            // user must be member of security group
            if (clientConfig.ActiveDirectoryGroup.Any())
            {
                var accessGroup = clientConfig.ActiveDirectoryGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (accessGroup != null)
                {
                    _logger.Debug("User '{User:l}' is member of '{AccessGroup:l}' access group in {BaseDn:l}", 
                        user, accessGroup.Trim(), profile.BaseDn);
                }
                else
                {
                    _logger.Warning("User '{User:l}' is not member of '{ActiveDirectoryGroup:l}' access group in {BaseDn:l}", 
                        user, string.Join(";", clientConfig.ActiveDirectoryGroup), profile.BaseDn);
                    return MembershipVerificationResult.Create(domain)
                        .SetSuccess(false)
                        .SetProfile(profile)
                        .Build();
                }
            }

            var resBuilder = MembershipVerificationResult.Create(domain)
                        .SetSuccess(true)
                        .SetProfile(profile);

            resBuilder.SetAre2FaGroupsSpecified(clientConfig.ActiveDirectory2FaGroup.Any());
            if (resBuilder.Subject.Are2FaGroupsSpecified)
            {
                var mfaGroup = clientConfig.ActiveDirectory2FaGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (mfaGroup != null)
                {
                    _logger.Debug("User '{User:l}' is member of '{MfaGroup:l}' 2FA group in {BaseDn:l}", user, mfaGroup.Trim(), profile.BaseDn);
                    resBuilder.SetIsMemberOf2FaGroups(true);
                }
                else
                {
                    _logger.Information("User '{User:l}' is not member of '{2FAGroup:l}' 2FA group in {BaseDn:l}", 
                        user, string.Join(";", clientConfig.ActiveDirectory2FaGroup), profile.BaseDn);
                }
            }

            resBuilder.SetAre2FaBypassGroupsSpecified(clientConfig.ActiveDirectory2FaBypassGroup.Any());
            if (resBuilder.Subject.Are2FaBypassGroupsSpecified)
            {
                var bypassGroup = clientConfig.ActiveDirectory2FaBypassGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (bypassGroup != null)
                {
                    _logger.Information("User '{User:l}' is member of '{BypassGroup:l}' 2FA bypass group in {BaseDn:l}", 
                        user, bypassGroup.Trim(), profile.BaseDn);
                    resBuilder.SetIsMemberOf2FaBypassGroup(true);
                }
                else
                {
                    _logger.Debug("User '{User:l}' is not member of '{ActiveDirectory2FaBypassGroup:l}' 2FA bypass group in {BaseDn:l}", 
                        user, string.Join(";", clientConfig.ActiveDirectory2FaBypassGroup), profile.BaseDn);
                }
            }

            return resBuilder.Build();
        }

        private bool IsMemberOf(LdapProfile profile, string group)
        {
            return profile.MemberOf?.Any(g => g.ToLower() == group.ToLower().Trim()) ?? false;
        }
    }
}