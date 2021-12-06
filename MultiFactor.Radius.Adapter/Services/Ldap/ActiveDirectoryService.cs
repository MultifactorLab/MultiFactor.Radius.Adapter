//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Services.Ldap;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
    public class ActiveDirectoryService : ILdapService
    {
        private Configuration _configuration;
        private ILogger _logger;

        private static IDictionary<string, LdapIdentity> _domainNameSuffixes;
        private static object _sync = new object();

        public ActiveDirectoryService(Configuration configuration, ILogger logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Verify User Name, Password, User Status and Policy against Active Directory
        /// </summary>
        public bool VerifyCredentialAndMembership(string userName, string password, PendingRequest request)
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
                if (!_configuration.IsPermittedDomain(suffix))
                {
                    _logger.Warning($"User domain {suffix} not permitted");
                    return false;
                }
            }
            else
            {
                if (_configuration.RequiresUpn)
                {
                    _logger.Warning("Only UserPrincipalName format permitted, see configuration");
                    return false;
                }
            }

            try
            {
                _logger.Debug($"Verifying user '{{user:l}}' credential and status at {_configuration.ActiveDirectoryDomain}", user.Name);

                using (var connection = new LdapConnection(_configuration.ActiveDirectoryDomain))
                {
                    connection.Credential = new NetworkCredential(user.Name, password);
				    connection.SessionOptions.RootDseCache = true;
                    connection.Bind();

                    _logger.Information($"User '{{user:l}}' credential and status verified successfully in {_configuration.ActiveDirectoryDomain}", user.Name);

                    return VerifyMembership(connection, user, request);
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
                        _logger.Warning($"Verification user '{{user:l}}' at {_configuration.ActiveDirectoryDomain} failed: {dataReason}", user.Name);
                        return false;
                    }
                }

                _logger.Error(lex, $"Verification user '{{user:l}}' at {_configuration.ActiveDirectoryDomain} failed", user.Name);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Verification user '{{user:l}}' at {_configuration.ActiveDirectoryDomain} failed", user.Name);
            }

            return false;
        }
        public bool VerifyMembership(string userName, PendingRequest request)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException(nameof(userName));
            }

            var user = LdapIdentity.ParseUser(userName);
            if (user.Type == IdentityType.UserPrincipalName)
            {
                var suffix = user.UpnToSuffix();
                if (!_configuration.IsPermittedDomain(suffix))
                {
                    _logger.Warning($"User domain {suffix} not permitted");
                    return false;
                }
            }
            else
            {
                if (_configuration.RequiresUpn)
                {
                    _logger.Warning("Only UserPrincipalName format permitted, see configuration");
                    return false;
                }
            }

            try
            {
                _logger.Debug($"Verifying user '{{user:l}}' membership at {_configuration.ActiveDirectoryDomain}", user.Name);

                using (var connection = new LdapConnection(_configuration.ActiveDirectoryDomain))
                {
                    connection.SessionOptions.RootDseCache = true;
                    connection.Bind();

                    return VerifyMembership(connection, user, request);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Verification user '{{user:l}}' membership at {_configuration.ActiveDirectoryDomain} failed", user.Name);
                _logger.Information("Run MultiFactor.Raduis.Adapter as user with domain read permissions (basically any domain user)");
            }

            return false;
        }

        /// <summary>
        /// Change user password
        /// </summary>
        public bool ChangePassword(string userName, string currentPassword, string newPassword, out bool passwordDoesNotMeetRequirements)
        {
            var identity = LdapIdentity.ParseUser(userName);
            passwordDoesNotMeetRequirements = false;

            try
            {
                LdapProfile userProfile;

                using (var connection = new LdapConnection(_configuration.ActiveDirectoryDomain))
                {
                    connection.Bind();

                    var domain = LdapIdentity.FqdnToDn(_configuration.ActiveDirectoryDomain);

                    var isProfileLoaded = LoadProfile(connection, domain, identity, out var profile);
                    if (!isProfileLoaded)
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

        private bool VerifyMembership(LdapConnection connection, LdapIdentity user, PendingRequest request)
        {
            var domain = LdapIdentity.FqdnToDn(_configuration.ActiveDirectoryDomain);

            LoadForestSchema(connection, domain);

            var isProfileLoaded = LoadProfile(connection, domain, user, out var profile);
            if (!isProfileLoaded)
            {
                return false;
            }

            var checkGroupMembership = !string.IsNullOrEmpty(_configuration.ActiveDirectoryGroup);
            //user must be member of security group
            if (checkGroupMembership)
            {
                var isMemberOf = IsMemberOf(connection, profile, user, _configuration.ActiveDirectoryGroup);

                if (!isMemberOf)
                {
                    _logger.Warning($"User '{{user:l}}' is not member of '{_configuration.ActiveDirectoryGroup}' group in {profile.BaseDn.Name}", user.Name);
                    return false;
                }

                _logger.Debug($"User '{{user:l}}' is member of '{_configuration.ActiveDirectoryGroup}' group in {profile.BaseDn.Name}", user.Name);
            }

            var onlyMembersOfGroupMustProcess2faAuthentication = !string.IsNullOrEmpty(_configuration.ActiveDirectory2FaGroup);
            //only users from group must process 2fa
            if (onlyMembersOfGroupMustProcess2faAuthentication)
            {
                var isMemberOf = IsMemberOf(connection, profile, user, _configuration.ActiveDirectory2FaGroup);

                if (isMemberOf)
                {
                    _logger.Debug($"User '{{user:l}}' is member of '{_configuration.ActiveDirectory2FaGroup}' in {profile.BaseDn.Name}", user.Name);
                }
                else
                {
                    _logger.Information($"User '{{user:l}}' is not member of '{_configuration.ActiveDirectory2FaGroup}' in {profile.BaseDn.Name}", user.Name);
                    request.Bypass2Fa = true;
                }
            }

            //check groups membership for radius reply conditional attributes
            foreach (var attribute in _configuration.RadiusReplyAttributes)
            {
                foreach (var value in attribute.Value.Where(val => val.UserGroupCondition != null))
                {
                    if (IsMemberOf(connection, profile, user, value.UserGroupCondition))
                    {
                        _logger.Information($"User '{{user:l}}' is member of '{value.UserGroupCondition}' in {profile.BaseDn.Name}. Adding attribute '{attribute.Key}:{value.Value}' to reply", user.Name);
                        request.UserGroups.Add(value.UserGroupCondition);
                    }
                    else
                    {
                        _logger.Debug($"User '{{user:l}}' is not member of '{value.UserGroupCondition}' in {profile.BaseDn.Name}", user.Name);
                    }
                }
            }

            if (_configuration.UseActiveDirectoryUserPhone)
            {
                request.UserPhone = profile.Phone;
            }
            if (_configuration.UseActiveDirectoryMobileUserPhone)
            {
                request.UserPhone = profile.Mobile;
            }

            request.DisplayName = profile.DisplayName;
            request.EmailAddress = profile.Email;

            return true;
        }

        private void LoadForestSchema(LdapConnection connection, LdapIdentity root)
        {
            if (_domainNameSuffixes != null)
            {
                return; //already loaded
            }

            _logger.Debug($"Loading forest schema from {root.Name}");

            try
            {
                lock (_sync)
                {
                    _domainNameSuffixes = new Dictionary<string, LdapIdentity>();
                    
                    var trustedDomainsResult = Query(connection,
                        "CN=System," + root.Name,
                        "objectClass=trustedDomain",
                        SearchScope.OneLevel,
                        true,
                        "cn");

                    var schema = new List<LdapIdentity>
                    {
                        root
                    };

                    for (var i = 0; i < trustedDomainsResult.Entries.Count; i++)
                    {
                        var entry = trustedDomainsResult.Entries[i];
                        var attribute = entry.Attributes["cn"];
                        if (attribute != null)
                        {
                            var domain = attribute[0].ToString();
                            if (_configuration.IsPermittedDomain(domain))
                            {
                                var trustPartner = LdapIdentity.FqdnToDn(domain);

                                _logger.Debug($"Found trusted domain {trustPartner.Name}");

                                if (!schema.Contains(trustPartner))
                                {
                                    schema.Add(trustPartner);
                                }
                            }
                        }
                    }

                    foreach(var domain in schema)
                    {
                        var domainSuffix = domain.DnToFqdn();
                        if (!_domainNameSuffixes.ContainsKey(domainSuffix))
                        {
                            _domainNameSuffixes.Add(domainSuffix, domain);
                        }

                        var isChild = schema.Any(parent => domain.IsChildOf(parent));
                        if (!isChild)
                        {
                            try
                            {
                                var uPNSuffixesResult = Query(connection,
                                    "CN=Partitions,CN=Configuration," + domain.Name,
                                    "objectClass=*",
                                    SearchScope.Base,
                                    true,
                                    "uPNSuffixes");

                                for (var i = 0; i < uPNSuffixesResult.Entries.Count; i++)
                                {
                                    var entry = uPNSuffixesResult.Entries[i];
                                    var attribute = entry.Attributes["uPNSuffixes"];
                                    if (attribute != null)
                                    {
                                        for (var j = 0; j < attribute.Count; j++)
                                        {
                                            var suffix = attribute[j].ToString();

                                            if (!_domainNameSuffixes.ContainsKey(suffix))
                                            {
                                                _domainNameSuffixes.Add(suffix, domain);
                                                _logger.Debug($"Found alternative UPN suffix {suffix} for domain {domain.Name}");
                                            }
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.Warning($"Unable to query {domain.Name}: {ex.Message}");
                            }
                        }
                    }
                }
            }
            catch(Exception ex)
            {
                _logger.Error(ex, "Unable to load forest schema");
            }
        }

        private bool LoadProfile(LdapConnection connection, LdapIdentity domain, LdapIdentity user, out LdapProfile profile)
        {
            profile = null;

            var attributes = new[] { "DistinguishedName", "displayName", "mail", "telephoneNumber", "mobile" };
            var searchFilter = $"(&(objectClass=user)({user.TypeName}={user.Name}))";

            var baseDn = SelectBestDomainToQuery(user, domain);

            _logger.Debug($"Querying user '{{user:l}}' in {baseDn.Name}", user.Name);

            //only this domain
            var response = Query(connection, baseDn.Name, searchFilter, SearchScope.Subtree, false, attributes);

            if (response.Entries.Count == 0)
            {
                //with ReferralChasing 
                response = Query(connection, baseDn.Name, searchFilter, SearchScope.Subtree, true, attributes);
            }

            if (response.Entries.Count == 0)
            {
                _logger.Error($"Unable to find user '{{user:l}}' in {baseDn.Name}", user.Name);
                return false;
            }

            var entry = response.Entries[0];

            profile = new LdapProfile
            {
                BaseDn = LdapIdentity.BaseDn(entry.DistinguishedName),
                DistinguishedName = entry.DistinguishedName,
                DisplayName = entry.Attributes["displayName"]?[0]?.ToString(),
                Email = entry.Attributes["mail"]?[0]?.ToString(),
                Phone = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                Mobile = entry.Attributes["mobile"]?[0]?.ToString(),
            };

            _logger.Debug($"User '{{user:l}}' profile loaded: {profile.DistinguishedName}", user.Name);

            return true;
        }

        private bool IsMemberOf(LdapConnection connection, LdapProfile profile, LdapIdentity user, string groupName)
        {
            var baseDn = SelectBestDomainToQuery(user, profile.BaseDn);
            var isValidGroup = IsValidGroup(connection, baseDn, groupName, out var group);

            if (!isValidGroup)
            {
                _logger.Warning($"Security group '{groupName}' not exists in {profile.BaseDn.Name}");
                return false;
            }

            var searchFilter = $"(&({user.TypeName}={user.Name})(memberOf:1.2.840.113556.1.4.1941:={group.Name}))";
            var response = Query(connection, profile.DistinguishedName, searchFilter, SearchScope.Subtree, true, "DistinguishedName");

            return response.Entries.Count > 0;
        }

        private bool IsValidGroup(LdapConnection connection, LdapIdentity domain, string groupName, out LdapIdentity validatedGroup)
        {
            validatedGroup = null;

            var group = LdapIdentity.ParseGroup(groupName);
            var searchFilter = $"(&(objectCategory=group)({group.TypeName}={group.Name}))";
            
            var response = Query(connection, domain.Name, searchFilter, SearchScope.Subtree, false, "DistinguishedName");
            if (response.Entries.Count == 0)
            {
                response = Query(connection, domain.Name, searchFilter, SearchScope.Subtree, true, "DistinguishedName");
            }

            for (var i=0; i < response.Entries.Count; i++)
            {
                var entry = response.Entries[i];
                var baseDn = LdapIdentity.BaseDn(entry.DistinguishedName);
                if (baseDn.Name == domain.Name) //only from user domain
                {
                    validatedGroup = new LdapIdentity
                    {
                        Name = entry.DistinguishedName,
                        Type = IdentityType.DistinguishedName
                    };

                    return true;
                }
            }

            return false;
        }

        private SearchResponse Query(LdapConnection connection, string baseDn, string filter, SearchScope scope, bool chaseRefs, params string[] attributes)
        {
            var searchRequest = new SearchRequest
                (baseDn,
                 filter,
                 scope,
                 attributes);

            if (chaseRefs)
            {
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.All;
            }
            else
            {
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            }

            var sw = Stopwatch.StartNew();

            var response = (SearchResponse)connection.SendRequest(searchRequest);

            if (sw.Elapsed.TotalSeconds > 2)
            {
                _logger.Warning($"Slow response while querying {baseDn}. Elapsed {sw.Elapsed}");
            }

            return response;
        }

        private LdapIdentity SelectBestDomainToQuery(LdapIdentity user, LdapIdentity defaultDomain)
        {
            if (user.Type != IdentityType.UserPrincipalName)
            {
                return defaultDomain;
            }

            if (_domainNameSuffixes == null)
            {
                return defaultDomain;
            }

            var userDomainSuffix = user.UpnToSuffix().ToLower();
            
            //best match
            foreach (var key in _domainNameSuffixes.Keys)
            {
                if (userDomainSuffix == key.ToLower())
                {
                    return _domainNameSuffixes[key];
                }
            }

            //approximately match
            foreach (var key in _domainNameSuffixes.Keys)
            {
                if (userDomainSuffix.EndsWith(key.ToLower()))
                {
                    return _domainNameSuffixes[key];
                }
            }

            return defaultDomain;
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
}