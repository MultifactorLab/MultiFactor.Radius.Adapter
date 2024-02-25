//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Interop;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;

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

        public ActiveDirectoryService(string domain, ForestMetadataCache forestMetadataCache, NetbiosService netbiosService, ILogger logger)
        {
            _domain = domain ?? throw new ArgumentNullException(nameof(domain));
            _forestMetadataCache = forestMetadataCache ?? throw new ArgumentNullException(nameof(forestMetadataCache));
            _netbiosService = netbiosService ?? throw new ArgumentNullException(nameof(netbiosService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Verify User Name, Password, User Status and Policy against Active Directory
        /// </summary>
        public bool VerifyCredentialAndMembership(ClientConfiguration clientConfig, string userName, string password, PendingRequest request)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException(nameof(userName));
            }
            if (string.IsNullOrEmpty(password))
            {
                _logger.Error("Empty password provided for user '{user:l}'", userName);
                return false;
            }

            var user = LdapIdentity.ParseUser(userName);
            var userDomain = _domain;

            if (clientConfig.RequiresUpn && user.Type != IdentityType.UserPrincipalName)
            {
                _logger.Warning("Only UserPrincipalName format permitted, see configuration");
                return false;
            }

            if (user.HasNetbiosName())
            {
                user = _netbiosService.ConvertToUpnUser(clientConfig, user, userDomain);
            }

            if (user.Type == IdentityType.UserPrincipalName)
            {
                var suffix = user.UpnToSuffix();
                if (!clientConfig.IsPermittedDomain(suffix))
                {
                    _logger.Warning($"User domain {suffix} not permitted");
                    return false;
                }
            }

            try
            {
                _logger.Debug($"Verifying user '{{user:l}}' credential and status at {userDomain}", user.Name);

                using (var connection = new LdapConnection(_domain))
                {
                    connection.Credential = new NetworkCredential(user.Name, password);
                    connection.SessionOptions.RootDseCache = true;
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.Bind();

                    _logger.Information($"User '{{user:l}}' credential and status verified successfully in {userDomain}", user.Name);

                    return VerifyMembership(clientConfig, connection, userDomain, user, request);
                }
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
                        _logger.Warning($"Verification user '{{user:l}}' at {userDomain} failed: {reason.ReasonText}", user.Name);
                        return false;
                    }
                }

                _logger.Error(lex, "Verification user '{user:l}' at {domain:l} failed: {msg:l} {srvmsg:l}", user.Name, userDomain, lex.Message, lex.ServerErrorMessage);
            }

            catch (Exception ex)
            {
                _logger.Error(ex, "Verification user '{user:l}' at {domain:l} failed: {msg:l}", user.Name, userDomain, ex.Message);
            }

            return false;
        }

        /// <summary>
        /// Change user password
        /// </summary>
        public bool ChangePassword(ClientConfiguration clientConfig, string userName, string currentPassword, string newPassword, out bool passwordDoesNotMeetRequirements)
        {
            var identity = LdapIdentity.ParseUser(userName);
            passwordDoesNotMeetRequirements = false;

            try
            {
                LdapProfile userProfile;

                using (var connection = new LdapConnection(_domain))
                {
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.SessionOptions.RootDseCache = true;
                    connection.Bind();

                    var domain = LdapIdentity.FqdnToDn(_domain);
                    var schema = _forestMetadataCache.Get(
                        clientConfig.Name,
                        domain,
                        () => new ForestSchemaLoader(clientConfig, connection, _logger).Load(domain));

                    if (identity.HasNetbiosName())
                    {
                        _logger.Information($"Trying to resolve domain by netbios {identity.NetBiosName} for password changing, user:{identity.Name}.");
                        identity = _netbiosService.ConvertToUpnUser(clientConfig, identity, _domain);
                        domain = LdapIdentity.FqdnToDn(identity.UpnToSuffix());
                    }

                    var profile = new ProfileLoader(schema, _logger).LoadProfile(clientConfig, connection, domain, identity);
                    if (profile == null)
                    {
                        return false;
                    }

                    userProfile = profile;
                }

                _logger.Debug($"Changing password for user '{{user:l}}' in {userProfile.BaseDn.DnToFqdn()}", identity.Name);
                using (var ctx = new PrincipalContext(ContextType.Domain, userProfile.BaseDn.DnToFqdn(), null, ContextOptions.Negotiate))
                {
                    using (var user = UserPrincipal.FindByIdentity(ctx, IdentityType.DistinguishedName, userProfile.DistinguishedName))
                    {
                        user.ChangePassword(currentPassword, newPassword);
                        user.Save();
                    }
                }

                _logger.Information("Password changed for user '{user:l}'", identity.Name);
                return true;
            }
            catch (PasswordException pex)
            {
                _logger.Warning("Changing password for user '{user:l}' failed: {Message}, {HResult}", identity.Name, pex.Message, pex.HResult);
                passwordDoesNotMeetRequirements = true;
            }
            catch (Exception ex)
            {
                _logger.Warning("Changing password for user '{user:l}' failed: {Message}", identity.Name, ex.Message);
            }

            return false;
        }

        private bool VerifyMembership(ClientConfiguration clientConfig, LdapConnection connection, string userDomain, LdapIdentity user, PendingRequest request)
        {
            var domain = LdapIdentity.FqdnToDn(userDomain);
            var schema = _forestMetadataCache.Get(
                clientConfig.Name,
                domain,
                () => new ForestSchemaLoader(clientConfig, connection, _logger).Load(domain));
            var profile = new ProfileLoader(schema, _logger).LoadProfile(clientConfig, connection, domain, user);
            if (profile == null)
            {
                return false;
            }

            //user must be member of security group
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
                    return false;
                }
            }

            //only users from group must process 2fa
            if (clientConfig.ActiveDirectory2FaGroup.Any())
            {
                var mfaGroup = clientConfig.ActiveDirectory2FaGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (mfaGroup != null)
                {
                    _logger.Debug($"User '{{user:l}}' is member of '{mfaGroup.Trim()}' 2FA group in {profile.BaseDn.Name}", user.Name);
                }
                else
                {
                    _logger.Information($"User '{{user:l}}' is not member of '{string.Join(";", clientConfig.ActiveDirectory2FaGroup)}' 2FA group in {profile.BaseDn.Name}", user.Name);
                    request.Bypass2Fa = true;
                }
            }

            if (!request.Bypass2Fa && clientConfig.ActiveDirectory2FaBypassGroup.Any())
            {
                var bypassGroup = clientConfig.ActiveDirectory2FaBypassGroup.FirstOrDefault(group => IsMemberOf(profile, group));
                if (bypassGroup != null)
                {
                    _logger.Information($"User '{{user:l}}' is member of '{bypassGroup.Trim()}' 2FA bypass group in {profile.BaseDn.Name}", user.Name);
                    request.Bypass2Fa = true;
                }
                else
                {
                    _logger.Debug($"User '{{user:l}}' is not member of '{string.Join(";", clientConfig.ActiveDirectory2FaBypassGroup)}' 2FA bypass group in {profile.BaseDn.Name}", user.Name);
                }
            }

            request.UpdateProfile(profile);

            if (profile.MemberOf.Count != 0)
            {
                request.UserGroups = profile.MemberOf;
            }

            return true;
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