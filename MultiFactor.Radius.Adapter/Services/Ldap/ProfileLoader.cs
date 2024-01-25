//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class ProfileLoader
    {
        private readonly ForestSchema _forestSchema;
        private readonly ILogger _logger;

        public ProfileLoader(ForestSchema forestSchema, ILogger logger)
        {
            _forestSchema = forestSchema ?? throw new ArgumentNullException(nameof(forestSchema));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public LdapProfile LoadProfile(ClientConfiguration clientConfig, LdapConnection connection, LdapIdentity domain, LdapIdentity user)
        {
            var profile = new LdapProfile();

            var queryAttributes = new List<string> { "DistinguishedName", "displayName", "mail", "memberOf", "userPrincipalName" };

            // if an attribute is set for the second factor and it is a new attribute
            if (clientConfig.TwoFAIdentityAttribyte != null && !queryAttributes.Contains(clientConfig.TwoFAIdentityAttribyte))
            {
                queryAttributes.Add(clientConfig.TwoFAIdentityAttribyte);
            }

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
            profile.SecondFactorIdentity = clientConfig.TwoFAIdentityAttribyte == null ? null : result.Entry.Attributes[clientConfig.TwoFAIdentityAttribyte]?[0]?.ToString();

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
            foreach (var phoneAttr in clientConfig.PhoneAttributes)
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

            _logger.Debug($"User '{{user:l}}' profile loaded: {profile.DistinguishedName} (upn={{upn:l}})", user.Name, profile.Upn);

            //nested groups if configured
            if (clientConfig.ShouldLoadUserGroups())
            {
                LoadAllUserGroups(clientConfig, connAdapter, result.BaseDn, profile);
            }
            return profile;
        }

        public Dictionary<string, string[]> LoadAttributes(LdapConnection connection, LdapIdentity domain, LdapIdentity user, params string[] attrs)
        {
            var baseDnList = GetBaseDnList(user, domain);
            var connAdapter = new LdapConnectionAdapter(connection, _logger);
            var result = FindUser(user, baseDnList, connAdapter, attrs.ToArray());
            if (result == null)
            {
                _logger.Error($"Unable to find user '{{user:l}}' in {string.Join(", ", baseDnList.Select(x => $"({x})"))}", user.Name);
                return new Dictionary<string, string[]>();
            }

            var attributes = new Dictionary<string, string[]>();
            foreach (var a in attrs)
            {
                var loadedAttributeValues = result.Entry.Attributes[a];
                if (loadedAttributeValues == null || loadedAttributeValues.Capacity == 0) continue;
                attributes[a] = loadedAttributeValues.GetValues(typeof(string)).Select(x => x.ToString()).ToArray();
            }

            return attributes;
        }

        private IReadOnlyList<LdapIdentity> GetBaseDnList(LdapIdentity user, LdapIdentity domain)
        {
            switch (user.Type)
            {
                case IdentityType.SamAccountName:
                    return _forestSchema.DomainNameSuffixes
                        .Select(x => x.Value)
                        .Distinct(new LdapDomainEqualityComparer())
                        .ToArray();
                case IdentityType.UserPrincipalName: return new[] { _forestSchema.GetMostRelevanteDomain(user, domain) };
                default: return new[] { domain };
            }
        }

        private UserSearchResult FindUser(LdapIdentity user, IReadOnlyList<LdapIdentity> baseDnList, LdapConnectionAdapter connectionAdapter, params string[] attrs)
        {
            // search by netbios\name does not work
            // therefore, even a user with netbios needs to be searched by upn
            // however, if we are looking for a user with an alternative suffix, we need to use sAMAccountName instead of upn
            var searchFilter = user.HasNetbiosName()
                ? $"(&(objectClass=user)(|({user.TypeName}={user.Name})({IdentityType.SamAccountName}={user.Name.Split('@')[0]})))"
                : $"(&(objectClass=user)({user.TypeName}={user.Name}))";

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

        private void LoadAllUserGroups(ClientConfiguration clientConfig, LdapConnectionAdapter connectionAdapter, LdapIdentity baseDn, LdapProfile profile)
        {
            if (!clientConfig.LoadActiveDirectoryNestedGroups) return;

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