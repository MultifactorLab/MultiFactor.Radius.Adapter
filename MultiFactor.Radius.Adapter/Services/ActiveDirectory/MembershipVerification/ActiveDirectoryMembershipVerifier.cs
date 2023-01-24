//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.Connection;
using MultiFactor.Radius.Adapter.Services.Ldap.ProfileLoading;
using Serilog;
using System;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    public class ActiveDirectoryMembershipVerifier
    {
        private readonly ILogger _logger;
        private readonly ProfileLoaderFactory _profileLoaderFactory;

        public ActiveDirectoryMembershipVerifier(ILogger logger, ProfileLoaderFactory profileLoaderFactory)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _profileLoaderFactory = profileLoaderFactory ?? throw new ArgumentNullException(nameof(profileLoaderFactory));
        }

        /// <summary>
        /// Validate user membership within Active Directory Domain without password authentication
        /// </summary>
        public ComplexMembershipVerificationResult VerifyMembership(PendingRequest request, ClientConfiguration clientConfig)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));
            if (clientConfig is null) throw new ArgumentNullException(nameof(clientConfig));

            var result = new ComplexMembershipVerificationResult();

            var userName = request.UserName;
            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return result;
            }

            LdapProfile profile = null;

            //trying to authenticate for each domain/forest
            foreach (var domain in clientConfig.SplittedActiveDirectoryDomains)
            {
                var domainIdentity = LdapIdentity.FqdnToDn(domain);

                try
                {
                    var user = LdapIdentityFactory.CreateUserIdentity(clientConfig, userName);

                    _logger.Debug($"Verifying user '{{user:l}}' membership at {domainIdentity}", user.Name);
                    using (var connection = LdapConnectionFactory.CreateConnection(domain))
                    {
                        var loader = _profileLoaderFactory.CreateLoader(clientConfig, connection);
                        if (profile == null)
                        {
                            profile = loader.LoadProfile(user, domainIdentity);
                            if (profile == null)
                            {
                                result.AddDomainResult(MembershipVerificationResult.Create(domainIdentity)
                                    .SetSuccess(false)
                                    .Build());
                                continue;
                            }
                        }

                        var res = VerifyMembership(clientConfig, profile, domainIdentity, user);
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
                    _logger.Error(ex, $"Verification user '{{user:l}}' membership at {domainIdentity} failed", userName);
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
                    _logger.Debug($"User '{{user:l}}' is member of '{accessGroup.Trim()}' access group in {profile.BaseDn.Name}", user.Name);
                }
                else
                {
                    _logger.Warning($"User '{{user:l}}' is not member of '{string.Join(";", clientConfig.ActiveDirectoryGroup)}' access group in {profile.BaseDn.Name}", user.Name);
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
                    _logger.Debug($"User '{{user:l}}' is member of '{mfaGroup.Trim()}' 2FA group in {profile.BaseDn.Name}", user.Name);
                    resBuilder.SetIsMemberOf2FaGroups(true);
                }
                else
                {
                    _logger.Information($"User '{{user:l}}' is not member of '{string.Join(";", clientConfig.ActiveDirectory2FaGroup)}' 2FA group in {profile.BaseDn.Name}", user.Name);
                }
            }

            resBuilder.SetAre2FaBypassGroupsSpecified(clientConfig.ActiveDirectory2FaBypassGroup.Any());
            if (resBuilder.Subject.Are2FaBypassGroupsSpecified)
            {
                var bypassGroup = clientConfig.ActiveDirectory2FaBypassGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (bypassGroup != null)
                {
                    _logger.Information($"User '{{user:l}}' is member of '{bypassGroup.Trim()}' 2FA bypass group in {profile.BaseDn.Name}", user.Name);
                    resBuilder.SetIsMemberOf2FaBypassGroup(true);
                }
                else
                {
                    _logger.Debug($"User '{{user:l}}' is not member of '{string.Join(";", clientConfig.ActiveDirectory2FaBypassGroup)}' 2FA bypass group in {profile.BaseDn.Name}", user.Name);
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