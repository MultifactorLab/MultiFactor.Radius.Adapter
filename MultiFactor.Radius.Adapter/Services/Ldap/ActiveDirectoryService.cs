//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Server;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    /// <summary>
    /// Service to interact with Active Directory
    /// </summary>
    public class ActiveDirectoryService
    {
        private ILogger _logger;

        private ForestSchema _forestSchema;
        private readonly object _sync = new object();

        private string _domain;

        public ActiveDirectoryService(ILogger logger, string domain)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _domain = domain ?? throw new ArgumentNullException(nameof(domain));
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
                _logger.Debug($"Verifying user '{{user:l}}' credential and status at {_domain}", user.Name);

                using (var connection = new LdapConnection(_domain))
                {
                    connection.Credential = new NetworkCredential(user.Name, password);
				    connection.SessionOptions.RootDseCache = true;
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.Bind();

                    _logger.Information($"User '{{user:l}}' credential and status verified successfully in {_domain}", user.Name);

                    return VerifyMembership(clientConfig, connection, user, request);
                }
            }
            catch (LdapException lex)
            {
                if (lex.ServerErrorMessage != null)
                {
                    var dataReason = ExtractErrorReason(lex.ServerErrorMessage, out var mustChangePassword);
                    request.MustChangePassword = mustChangePassword;

                    if (dataReason != null)
                    {
                        _logger.Warning($"Verification user '{{user:l}}' at {_domain} failed: {dataReason}", user.Name);
                        return false;
                    }
                }

                _logger.Error($"Verification user '{{user:l}}' at {_domain} failed: {lex.Message} {lex.ServerErrorMessage}", user.Name);
            }
            catch (Exception ex)
            {
                _logger.Error($"Verification user '{{user:l}}' at {_domain} failed: {ex.Message}", user.Name);
            }

            return false;
        }
        public bool VerifyMembership(ClientConfiguration clientConfig, string userName, PendingRequest request)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException(nameof(userName));
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
                _logger.Debug($"Verifying user '{{user:l}}' membership at {_domain}", user.Name);

                using (var connection = new LdapConnection(_domain))
                {
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.SessionOptions.RootDseCache = true;
                    connection.Bind();

                    return VerifyMembership(clientConfig, connection, user, request);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Verification user '{{user:l}}' membership at {_domain} failed", user.Name);
                _logger.Information("Run MultiFactor.Raduis.Adapter as user with domain read permissions (basically any domain user)");
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

                    var profile = LoadProfile(clientConfig, connection, domain, identity);
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

            LoadForestSchema(clientConfig, connection, domain);

            var profile = LoadProfile(clientConfig, connection, domain, user);
            if (profile == null)
            {
                return false;
            }

            var checkGroupMembership = clientConfig.ActiveDirectoryGroup.Any();
            //user must be member of security group
            if (checkGroupMembership)
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

            var onlyMembersOfGroupMustProcess2faAuthentication = clientConfig.ActiveDirectory2FaGroup.Any();
            //only users from group must process 2fa
            if (onlyMembersOfGroupMustProcess2faAuthentication)
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

            var onlyMembersOfGroupMustNotProcess2faAuthentication = clientConfig.ActiveDirectory2FaBypassGroup.Any();
            if (!request.Bypass2Fa && onlyMembersOfGroupMustNotProcess2faAuthentication)
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

        private void LoadForestSchema(ClientConfiguration clientConfig, LdapConnection connection, LdapIdentity root)
        {
            if (_forestSchema != null)
            {
                return; //already loaded
            }

            lock (_sync)
            {
                _forestSchema = new ForestSchemaLoader(clientConfig, connection, _logger).Load(root);
            }
        }

        private LdapProfile LoadProfile(ClientConfiguration clientConfig, LdapConnection connection, LdapIdentity domain, LdapIdentity user)
        {
            var profile = new LdapProfile();

            var queryAttributes = new List<string> { "DistinguishedName", "displayName", "mail", "memberOf", "userPrincipalName" };

            var ldapReplyAttributes = clientConfig.GetLdapReplyAttributes();
            foreach (var ldapReplyAttribute in ldapReplyAttributes)
            {
                if (!profile.LdapAttrs.ContainsKey(ldapReplyAttribute))
                {
                    profile.LdapAttrs.Add(ldapReplyAttribute, null);
                    queryAttributes.Add(ldapReplyAttribute);
                }
            }
            queryAttributes.AddRange(clientConfig.PhoneAttributes);

            var baseDnList = GetBaseDnList(user, domain);
            var connAdapter = new LdapConnectionAdapter(connection, _logger);
            var result = FindUser(user, baseDnList, connAdapter, queryAttributes.ToArray());
            if (result == null)
            {
                _logger.Error($"Unable to find user '{{user:l}}' in {string.Join(", ", baseDnList.Select(x => $"({x})"))}", user.Name);
                return null;
            }

            //base profile
            profile.BaseDn = LdapIdentity.BaseDn(result.Entry.DistinguishedName);
            profile.DistinguishedName = result.Entry.DistinguishedName;
            profile.DisplayName = result.Entry.Attributes["displayName"]?[0]?.ToString();
            profile.Email = result.Entry.Attributes["mail"]?[0]?.ToString();
            profile.Upn = result.Entry.Attributes["userPrincipalName"]?[0]?.ToString();

            //additional attributes for radius response
            foreach (var key in profile.LdapAttrs.Keys.ToList()) //to list to avoid collection was modified exception
            {
                if (result.Entry.Attributes.Contains(key))
                {
                    profile.LdapAttrs[key] = result.Entry.Attributes[key][0]?.ToString();
                }
            }

            //groups
            var memberOf = result.Entry.Attributes["memberOf"]?.GetValues(typeof(string));
            if (memberOf != null)
            {
                profile.MemberOf = memberOf.Select(dn => LdapIdentity.DnToCn(dn.ToString())).ToList();
            }

            //phone
            foreach(var phoneAttr in clientConfig.PhoneAttributes)
            {
                if (result.Entry.Attributes.Contains(phoneAttr))
                {
                    var phone = result.Entry.Attributes[phoneAttr][0]?.ToString();
                    if (!string.IsNullOrEmpty(phone))
                    {
                        profile.Phone = phone;
                        break;
                    }
                }
            }

            _logger.Debug($"User '{{user:l}}' profile loaded: {profile.DistinguishedName}", user.Name);

            //nested groups if configured
            if (clientConfig.ShouldLoadUserGroups())
            {
                LoadAllUserGroups(clientConfig, connAdapter, result.BaseDn, profile);
            }
            return profile;
        }

        private IReadOnlyList<LdapIdentity> GetBaseDnList(LdapIdentity user, LdapIdentity domain)
        {
            switch (user.Type)
            {
                case IdentityType.SamAccountName: return _forestSchema.DomainNameSuffixes
                        .Select(x => x.Value)
                        .Distinct(new LdapDomainEqualityComparer())
                        .ToArray();
                case IdentityType.UserPrincipalName: return new[] { _forestSchema.GetMostRelevanteDomain(user, domain) };
                default: return new[] { domain };
            }
        }

        private UserSearchResult FindUser(LdapIdentity user, IReadOnlyList<LdapIdentity> baseDnList, LdapConnectionAdapter connectionAdapter, params string[] attrs)
        {
            var searchFilter = $"(&(objectClass=user)({user.TypeName}={user.Name}))";

            foreach (var baseDn in baseDnList)
            {
                _logger.Debug($"Querying user '{{user:l}}' in {baseDn.Name}", user.Name);

                //only this domain
                var response = connectionAdapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree, 
                    false, 
                    attrs.Distinct().ToArray());

                if (response.Entries.Count != 0)
                {
                    return new UserSearchResult(response.Entries[0], baseDn);
                }

                //with ReferralChasing 
                response = connectionAdapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree, 
                    true, 
                    attrs.Distinct().ToArray());

                if (response.Entries.Count != 0)
                {
                    return new UserSearchResult(response.Entries[0], baseDn);
                }
            }

            return null;
        }

        private bool IsMemberOf(LdapProfile profile, string group)
        {
            return profile.MemberOf?.Any(g => g.ToLower() == group.ToLower().Trim()) ?? false;
        }

        private void LoadAllUserGroups(ClientConfiguration clientConfig, LdapConnectionAdapter connectionAdapter, LdapIdentity baseDn, LdapProfile profile)
        {
            if (!clientConfig.LoadActiveDirectoryNestedGroups) return;     

            var searchFilter = $"(member:1.2.840.113556.1.4.1941:={profile.DistinguishedName})";
            var response = connectionAdapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree, false, "DistinguishedName");

            var groups = new List<string>(response.Entries.Count);
            for (var i = 0; i < response.Entries.Count; i++)
            {
                var entry = response.Entries[i];
                groups.Add(LdapIdentity.DnToCn(entry.DistinguishedName));
            }

            profile.MemberOf = groups;
        }

        private string ExtractErrorReason(string errorMessage, out bool mustChangePassword)
        {
            mustChangePassword = false;

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
                        mustChangePassword = true;
                        return "password expired";
                    case "533":
                        return "account disabled";
                    case "701":
                        return "account expired";
                    case "773":
                        mustChangePassword = true;
                        return "user must change password";
                    case "775":
                        return "user account locked";
                }
            }

            return null;
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