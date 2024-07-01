//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory
{
    /// <summary>
    /// Service to interact with Active Directory
    /// </summary>
    public class ActiveDirectoryService
    {
        private readonly ILogger _logger;
        private readonly string _domain;
        private readonly ForestMetadataCache _forestMetadataCache;
        private readonly NetbiosService _netbiosService;
        private readonly LdapConnectionFactory _connectionFactory;

        public ActiveDirectoryService(string domain, 
            ForestMetadataCache forestMetadataCache, 
            NetbiosService netbiosService,
            LdapConnectionFactory connectionFactory,
            ILogger logger)
        {
            _domain = domain ?? throw new ArgumentNullException(nameof(domain));
            _forestMetadataCache = forestMetadataCache ?? throw new ArgumentNullException(nameof(forestMetadataCache));
            _netbiosService = netbiosService ?? throw new ArgumentNullException(nameof(netbiosService));
            _connectionFactory = connectionFactory;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Verify User Name, Password, User Status and Policy against Active Directory
        /// </summary>
        public bool VerifyCredentialAndMembership(PendingRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.UserName))
            {
                _logger.Error("Empty username provided for user", request.UserName);
                return false;
            }
            if (string.IsNullOrEmpty(request.Passphrase.Password))
            {
                _logger.Error("Empty password provided for user '{User:l}'", request.UserName);
                return false;
            }

            var user = LdapIdentity.ParseUser(request.UserName);
            if (request.Configuration.RequiresUpn && user.Type != IdentityType.UserPrincipalName)
            {
                _logger.Warning("Only UserPrincipalName format permitted, see configuration");
                return false;
            }

            if (user.HasNetbiosName())
            {
                user = _netbiosService.ConvertToUpnUser(request.Configuration, user, _domain);
            }

            if (user.Type == IdentityType.UserPrincipalName)
            {
                var suffix = user.UpnToSuffix();
                if (!request.Configuration.IsPermittedDomain(suffix))
                {
                    _logger.Warning("User domain {Suffix:l} not permitted", suffix);
                    return false;
                }
            }

            try
            {
                VerifyCredential(user, request);
                return VerifyMembership(request.Configuration, user, request);
            }
            catch (LdapException lex)
            {
                if (lex.ServerErrorMessage != null)
                {
                    var reason = LdapErrorReasonInfo.Create(lex.ServerErrorMessage);
                    if (reason.Flags.HasFlag(LdapErrorFlag.MustChangePassword))
                    {
                        request.SetMustChangePassword(_domain);
                    }

                    if (reason.Reason != LdapErrorReason.UnknownError)
                    {
                        _logger.Warning("Verification user '{User:l}' at {Domain:l} failed: {Reason:l}", user, _domain, reason.ReasonText);
                        return false;
                    }
                }

                _logger.Error(lex, "Verification user '{User:l}' at {Domain:l} failed: {Msg:l} {Srvmsg:l}", user, _domain, lex.Message, lex.ServerErrorMessage);
            }

            catch (Exception ex)
            {
                _logger.Error(ex, "Verification user '{User:l}' at {Domain:l} failed: {Msg:l}", user, _domain, ex.Message);
            }

            return false;
        }

        /// <summary>
        /// Change user password
        /// </summary>
        public bool ChangePassword(PendingRequest request, string currentPassword, out bool passwordDoesNotMeetRequirements)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrWhiteSpace(currentPassword))
            {
                throw new ArgumentException($"'{nameof(currentPassword)}' cannot be null or whitespace.", nameof(currentPassword));
            }

            var identity = LdapIdentity.ParseUser(request.UserName);
            passwordDoesNotMeetRequirements = false;

            try
            {
                LdapProfile userProfile;

                using (var connection = _connectionFactory.CreateAsCurrentProcessUser(_domain))
                {
                    var domain = LdapIdentity.FqdnToDn(_domain);
                    var schema = _forestMetadataCache.Get(
                        request.Configuration.Name,
                        domain,
                        () => new ForestSchemaLoader(request.Configuration, connection, _logger).Load(domain));

                    if (identity.HasNetbiosName())
                    {
                        _logger.Information("Trying to resolve domain by netbios {NetBiosName:l} for password changing, user:{identity:l}.", 
                            identity.NetBiosName , identity.Name);
                        identity = _netbiosService.ConvertToUpnUser(request.Configuration, identity, _domain);
                        domain = LdapIdentity.FqdnToDn(identity.UpnToSuffix());
                    }

                    var profile = new ProfileLoader(schema, _logger).LoadProfile(request.Configuration, connection, domain, identity);
                    if (profile == null)
                    {
                        return false;
                    }

                    userProfile = profile;
                }

                _logger.Debug("Changing password for user '{User:l}' in {BaseDn:l}", identity, userProfile.BaseDn.DnToFqdn());
                using (var ctx = new PrincipalContext(ContextType.Domain, userProfile.BaseDn.DnToFqdn(), null, ContextOptions.Negotiate))
                {
                    using (var user = UserPrincipal.FindByIdentity(ctx, IdentityType.DistinguishedName, userProfile.DistinguishedName))
                    {
                        user.ChangePassword(currentPassword, request.Passphrase.Raw);
                        user.Save();
                    }
                }

                _logger.Information("Password changed for user '{User:l}'", identity);
                return true;
            }
            catch (PasswordException pex)
            {
                _logger.Warning("Changing password for user '{User:l}' failed: {Message:l}, {HResult:l}", identity, pex.Message, pex.HResult);
                passwordDoesNotMeetRequirements = true;
            }
            catch (Exception ex)
            {
                _logger.Warning("Changing password for user '{User:l}' failed: {Message:l}", identity, ex.Message);
            }

            return false;
        }

        private bool VerifyMembership(ClientConfiguration clientConfig, LdapIdentity user, PendingRequest request)
        {
            var domain = LdapIdentity.FqdnToDn(_domain);

            LdapProfile profile;
            
            using (var connection = _connectionFactory.CreateAsCurrentProcessUser(_domain))
            {
                var forestSchema = _forestMetadataCache.Get(
                    clientConfig.Name,
                    domain,
                    () => new ForestSchemaLoader(clientConfig, connection, _logger).Load(domain));
                
                profile = new ProfileLoader(forestSchema, _logger).LoadProfile(clientConfig, connection, domain, user);
                
                if (profile == null)
                {
                    return false;
                }
            }

            //user must be member of security group
            if (clientConfig.ActiveDirectoryGroup.Any())
            {
                var accessGroup = clientConfig.ActiveDirectoryGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (accessGroup != null)
                {
                    _logger.Debug("User '{User:l}' is member of '{AccessGroup:l}' access group in {BaseDn:l}", 
                        user, accessGroup.Trim(), profile.BaseDn.Name);
                }
                else
                {
                    _logger.Warning("User '{User:l}' is not member of '{ActiveDirectoryGroup:l}' access group in {BaseDn:l}", 
                        user, string.Join(";", clientConfig.ActiveDirectoryGroup), profile.BaseDn.Name);
                    return false;
                }
            }

            //only users from group must process 2fa
            if (clientConfig.ActiveDirectory2FaGroup.Any())
            {
                var mfaGroup = clientConfig.ActiveDirectory2FaGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (mfaGroup != null)
                {
                    _logger.Debug("User '{User:l}' is member of '{MfaGroup:l}' 2FA group in {BaseDn:l}", 
                        user, mfaGroup.Trim(), profile.BaseDn.Name);
                }
                else
                {
                    _logger.Information("User '{User:l}' is not member of '{ActiveDirectory2FaGroup:l}' 2FA group in {BaseDn:l}", 
                        user, string.Join(";", clientConfig.ActiveDirectory2FaGroup), profile.BaseDn.Name);
                    request.AuthenticationState.SetSecondFactor(AuthenticationCode.Bypass);
                }
            }

            if (request.AuthenticationState.SecondFactor != AuthenticationCode.Bypass && clientConfig.ActiveDirectory2FaBypassGroup.Any())
            {
                var bypassGroup = clientConfig.ActiveDirectory2FaBypassGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (bypassGroup != null)
                {
                    _logger.Information("User '{{user:l}}' is member of '{BypassGroup:l}' 2FA bypass group in {BaseDn:l}", user, bypassGroup.Trim(), profile.BaseDn.Name);
                    request.AuthenticationState.SetSecondFactor(AuthenticationCode.Bypass);
                }
                else
                {
                    _logger.Debug("User '{User:l}' is not member of '{2FABypassGroups:l}' 2FA bypass group in {BaseDn:l}", user, string.Join(";", clientConfig.ActiveDirectory2FaBypassGroup), profile.BaseDn.Name);
                }
            }

            request.UpdateProfile(profile);

            if (profile.MemberOf.Count != 0)
            {
                request.UserGroups = profile.MemberOf;
            }

            return true;
        }

        private void VerifyCredential(LdapIdentity user, PendingRequest request)
        {
            _logger.Debug("Verifying user '{User:l}' credential and status at {Domain:l}", user, _domain);
            
            using (_ = _connectionFactory.Create(_domain, user.Name, request.Passphrase.Password))
            {
                _logger.Information("User '{User:l}' credential and status verified successfully in {Domain:l}", user, _domain);
            }
        }

        private bool IsMemberOf(LdapProfile profile, string group)
        {
            return profile.MemberOf?.Any(g => g.ToLower() == group.ToLower().Trim()) ?? false;
        }
    }

    public class UserSearchResult
    {
        public SearchResultEntry Entry { get; }
        public LdapIdentity BaseDn { get; }

        public UserSearchResult(SearchResultEntry entry, LdapIdentity baseDn)
        {
            Entry = entry ?? throw new ArgumentNullException(nameof(entry));
            BaseDn = baseDn ?? throw new ArgumentNullException(nameof(baseDn));
        }
    }

    public class LdapDomainEqualityComparer : IEqualityComparer<LdapIdentity>
    {
        public bool Equals(LdapIdentity x, LdapIdentity y)
        {
            if (x == null || y == null) return false;
            return x == y || x.Name == y.Name;
        }

        public int GetHashCode(LdapIdentity obj)
        {
            return obj.GetHashCode();
        }
    }
}