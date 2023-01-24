//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.Ldap.Connection;
using MultiFactor.Radius.Adapter.Services.Ldap.UserFinding;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap.ProfileLoading
{
    public class ProfileLoader
    {
        private readonly ILogger _logger;
        private readonly ClientConfiguration _clientConfig;
        private readonly LdapConnection _connection;
        private readonly LdapUserFinderFactory _ldapUserFinderFactory;

        public ProfileLoader(ClientConfiguration clientConfig, LdapConnection connection, LdapUserFinderFactory ldapUserFinderFactory, ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _clientConfig = clientConfig ?? throw new ArgumentNullException(nameof(clientConfig));
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            _ldapUserFinderFactory = ldapUserFinderFactory ?? throw new ArgumentNullException(nameof(ldapUserFinderFactory));
        }

        public LdapProfile LoadProfile(LdapIdentity user, LdapIdentity rootDomain)
        {
            var profile = new LdapProfile();
            var queryAttributes = new List<string> { "DistinguishedName", "displayName", "mail", "memberOf", "userPrincipalName" };

            var ldapReplyAttributes = _clientConfig.GetLdapReplyAttributes();
            foreach (var ldapReplyAttribute in ldapReplyAttributes)
            {
                if (!profile.LdapAttrs.ContainsKey(ldapReplyAttribute))
                {
                    profile.LdapAttrs.Add(ldapReplyAttribute, null);
                    queryAttributes.Add(ldapReplyAttribute);
                }
            }
            queryAttributes.AddRange(_clientConfig.PhoneAttributes);

            var userFinder = _ldapUserFinderFactory.CreateFinder(_clientConfig, _connection);
            var result = userFinder.FindInForest(user, rootDomain, queryAttributes.ToArray());
            if (result == null)
            {
                return null;
            }

            // base profile
            profile.BaseDn = LdapIdentity.BaseDn(result.Entry.DistinguishedName);
            profile.DistinguishedName = result.Entry.DistinguishedName;
            profile.DisplayName = result.Entry.Attributes["displayName"]?[0]?.ToString();
            profile.Email = result.Entry.Attributes["mail"]?[0]?.ToString();
            profile.Upn = result.Entry.Attributes["userPrincipalName"]?[0]?.ToString();

            // override additional attributes for radius response
            foreach (var key in profile.LdapAttrs.Keys.ToList()) //to list to avoid collection was modified exception
            {
                if (result.Entry.Attributes.Contains(key))
                {
                    profile.LdapAttrs[key] = result.Entry.Attributes[key][0]?.ToString();
                }
            }

            // groups
            var memberOf = result.Entry.Attributes["memberOf"]?.GetValues(typeof(string));
            if (memberOf != null)
            {
                profile.MemberOf = memberOf.Select(dn => LdapIdentity.DnToCn(dn.ToString())).ToList();
            }

            // phone
            foreach (var phoneAttr in _clientConfig.PhoneAttributes)
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

            // nested groups if configured
            if (_clientConfig.ShouldLoadUserGroups())
            {
                LoadAllUserGroups(_clientConfig, _connection, result.BaseDn, profile);
            }
            return profile;
        }

        private void LoadAllUserGroups(ClientConfiguration clientConfig, LdapConnection connection, LdapIdentity baseDn, LdapProfile profile)
        {
            if (!clientConfig.LoadActiveDirectoryNestedGroups) return;

            var connectionAdapter = new LdapConnectionAdapter(connection, _logger);
            var searchFilter = $"(member:1.2.840.113556.1.4.1941:={profile.DistinguishedName})";
            var response = connectionAdapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree, false, "DistinguishedName");
            if (response.Entries.Count == 0)
            {
                response = connectionAdapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree, true, "DistinguishedName");
            }

            profile.MemberOf = response.Entries
                .Cast<SearchResultEntry>()
                .Select(x => LdapIdentity.DnToCn(x.DistinguishedName))
                .ToList();
        }
    }
}