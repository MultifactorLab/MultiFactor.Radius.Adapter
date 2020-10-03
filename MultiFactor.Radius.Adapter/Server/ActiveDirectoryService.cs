using MultiFactor.Radius.Adapter.Core;
using Serilog;
using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text.RegularExpressions;

namespace MultiFactor.Radius.Adapter.Server
{
    /// <summary>
    /// Service to interact with Active Directory
    /// </summary>
    public class ActiveDirectoryService
    {
        private Configuration _configuration;
        private ILogger _logger;

        public ActiveDirectoryService(Configuration configuration, ILogger logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Verify User Name, Password, User Status and Policy against Active Directory
        /// </summary>
        public bool VerifyCredential(string userName, string password, PendingRequest request)
        {
            var login = Utils.CanonicalizeUserName(userName);
            
            try
            {
                _logger.Debug($"Verifying user {login} credential and status at {_configuration.ActiveDirectoryDomain}");

                using (var connection = new LdapConnection(_configuration.ActiveDirectoryDomain))
                {
                    connection.Credential = new NetworkCredential(login, password);
                    connection.Bind();
                }

                _logger.Information($"User {login} credential and status verified successfully at {_configuration.ActiveDirectoryDomain}");

                var checkGroupMembership = !string.IsNullOrEmpty(_configuration.ActiveDirectoryGroup);
                var onlyMembersOfGroupMustProcess2faAuthentication = !string.IsNullOrEmpty(_configuration.ActiveDirectory2FaGroup);

                using (var ctx = new PrincipalContext(ContextType.Domain, _configuration.ActiveDirectoryDomain, login, password))
                {
                    using (var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, login))
                    {
                        //user must be member of security group
                        if (checkGroupMembership)
                        {
                            _logger.Debug($"Verifying user {login} is member of {_configuration.ActiveDirectoryGroup} group");

                            var isMemberOf = IsMemberOf(user, _configuration.ActiveDirectoryGroup);

                            if (!isMemberOf)
                            {
                                _logger.Warning($"User {login} is NOT member of {_configuration.ActiveDirectoryGroup} group");
                                return false;
                            }

                            _logger.Information($"User {login} is member of {_configuration.ActiveDirectoryGroup} group");
                        }

                        //only users from group must process 2fa
                        if (onlyMembersOfGroupMustProcess2faAuthentication)
                        {
                            _logger.Debug($"Verifying user {login} is member of {_configuration.ActiveDirectory2FaGroup} group");

                            var isMemberOf = IsMemberOf(user, _configuration.ActiveDirectory2FaGroup);

                            if (isMemberOf)
                            {
                                _logger.Information($"User {login} is member of {_configuration.ActiveDirectory2FaGroup} group");
                            }
                            else
                            {
                                _logger.Information($"User {login} is NOT member of {_configuration.ActiveDirectory2FaGroup} group");
                                request.Bypass2Fa = true;
                            }
                        }

                        if (_configuration.UseActiveDirectoryUserPhone)
                        {
                            request.UserPhone = user.VoiceTelephoneNumber; //user phone from general settings
                        }

                        if (_configuration.UseActiveDirectoryMobileUserPhone)
                        {
                            using (var entry = user.GetUnderlyingObject() as DirectoryEntry)
                            {
                                if (entry != null)
                                {
                                    var mobile = entry.Properties["mobile"].Value as string;
                                    request.UserPhone = mobile; //user mobile phone from general settings
                                }
                            }
                        }

                        request.EmailAddress = user.EmailAddress;
                    }
                }

                return true; //OK
            }
            catch(LdapException lex)
            {
                if (lex.ServerErrorMessage != null)
                {
                    var dataReason = ExtractErrorReason(lex.ServerErrorMessage);
                    if (dataReason != null)
                    {
                        _logger.Warning($"Verification user {login} at {_configuration.ActiveDirectoryDomain} failed: {dataReason}");
                        return false;
                    }
                }

                _logger.Error(lex, $"Verification user {login} at {_configuration.ActiveDirectoryDomain} failed");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Verification user {login} at {_configuration.ActiveDirectoryDomain} failed");
            }

            return false;
        }

        private string ExtractErrorReason(string errorMessage)
        {
            var pattern = @"data ([0-9a-e]{3})";
            var match = Regex.Match(errorMessage, pattern);

            if (match.Success && match.Groups.Count == 2)
            {
                var data = match.Groups[1].Value;

                switch (data)
                {
                    case "525":
                        return "user not found";
                    case "52e":
                        return "invalid credentials";
                    case "530":
                        return "not permitted to logon at this time​";
                    case "531":
                        return "not permitted to logon at this workstation​";
                    case "532":
                        return "password expired";
                    case "533":
                        return "account disabled";
                    case "701":
                        return "account expired";
                    case "773":
                        return "user must change password";
                    case "775":
                        return "user account locked";
                }
            }

            return null;
        }

        public bool IsMemberOf(Principal principal, string groupName)
        {
            using (var group = GroupPrincipal.FindByIdentity(principal.Context, IdentityType.SamAccountName, groupName))
            {
                if (group == null)
                {
                    _logger.Warning($"Security group {groupName} not exists");
                    return false;
                }

                var filter = $"(&(sAMAccountName={principal.SamAccountName})(memberOf:1.2.840.113556.1.4.1941:={group.DistinguishedName}))";

                using (var searcher = new DirectorySearcher(filter))
                {
                    var result = searcher.FindOne();
                    return result != null;
                }
            }
        }
    }
}