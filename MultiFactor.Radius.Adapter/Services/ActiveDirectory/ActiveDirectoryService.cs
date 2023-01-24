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
        private ILogger _logger;
        private string _domain;
        private readonly ProfileLoaderFactory _profileLoaderFactory;

        public ActiveDirectoryService(string domain, ProfileLoaderFactory profileLoaderFactory, ILogger logger)
        {
            _domain = domain ?? throw new ArgumentNullException(nameof(domain));
            _profileLoaderFactory = profileLoaderFactory ?? throw new ArgumentNullException(nameof(profileLoaderFactory));
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
            if (user.Type == IdentityType.UserPrincipalName)
            {
                var suffix = user.UpnToSuffix();
                if (!clientConfig.IsPermittedDomain(suffix))
                {
                    _logger.Warning($"User domain {suffix} not permitted");
                    return false;
                }
            }
            else
            {
                if (clientConfig.RequiresUpn)
                {
                    _logger.Warning("Only UserPrincipalName format permitted, see configuration");
                    return false;
                }
            }

            try
            {
                _logger.Debug("Verifying user '{user:l}' credential and status at '{d:l}'", user.Name, _domain);

                using (var connection = LdapConnectionFactory.CreateConnection(_domain, user.Name, password))
                {
                    _logger.Information("User '{user:l}' credential and status verified successfully in '{d:l}'", user.Name, _domain);
                    return VerifyMembership(clientConfig, connection, user, request);
                }
            }
            catch (LdapException lex)
            {
                if (lex.ServerErrorMessage != null)
                {
                    var reason = LdapErrorReasonInfo.Create(lex.ServerErrorMessage);
                    request.MustChangePassword = reason.Flags.HasFlag(LdapErrorFlag.MustChangePassword);

                    if (reason.Reason != LdapErrorReason.UnknownError)
                    {
                        _logger.Warning("Verification user '{user:l}' at '{d:l}' failed: {reason:l}", user.Name, _domain, reason.ReasonText);
                        return false;
                    }
                }

                _logger.Error(lex, "Verification user '{user:l}' at {domain:l} failed: {msg:l} {srvmsg:l}", user.Name, _domain, lex.Message, lex.ServerErrorMessage);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Verification user '{user:l}' at {domain:l} failed: {msg:l}", user.Name, _domain, ex.Message);
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
                using (var connection = LdapConnectionFactory.CreateConnection(_domain))
                {
                    var domain = LdapIdentity.FqdnToDn(_domain);
                    var loader = _profileLoaderFactory.CreateLoader(clientConfig, connection);
                    var profile = loader.LoadProfile(identity, domain);
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

        private bool VerifyMembership(ClientConfiguration clientConfig, LdapConnection connection, LdapIdentity user, PendingRequest request)
        {
            var domain = LdapIdentity.FqdnToDn(_domain);
            var loader = _profileLoaderFactory.CreateLoader(clientConfig, connection);
            var profile = loader.LoadProfile(user, domain);
            if (profile == null)
            {
                return false;
            }

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
                    return false;
                }
            }

            // only users from group must process 2fa
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

            request.Upn = profile.Upn;
            request.DisplayName = profile.DisplayName;
            request.EmailAddress = profile.Email;
            request.UserPhone = profile.Phone;
            request.LdapAttrs = profile.LdapAttrs;

            if (profile.MemberOf != null)
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
}