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
            var baseDnList = GetBaseDnList(user, domain);
            var connAdapter = new LdapConnectionAdapter(connection, _logger);
            var queryAttributes = GetQueryAttributes(clientConfig);

            var result = FindUser(user, baseDnList, connAdapter, queryAttributes);
            if (result == null)
            {
                _logger.Error($"Unable to find user '{{user:l}}' in {string.Join(", ", baseDnList.Select(x => $"({x})"))}", user.Name);
                return null;
            }

            //base profile
            var profileAttributes = new LdapAttributes();
            var profile = new LdapProfile(LdapIdentity.BaseDn(result.Entry.DistinguishedName), profileAttributes, clientConfig);

            foreach (var attr in queryAttributes.Where(x => !x.Equals("memberof", StringComparison.OrdinalIgnoreCase)))
            {
                var value = result.Entry.Attributes[attr]?.GetValues(typeof(string)).Cast<string>().ToArray() ?? Array.Empty<string>();
                profileAttributes.Add(attr, value);
            }

            //groups
            var groups = result.Entry.Attributes.Contains("memberOf")
                ? result.Entry.Attributes["memberOf"].GetValues(typeof(string))
                : Array.Empty<object>();

            profileAttributes.Add("memberOf", groups.Cast<string>().Select(LdapIdentity.DnToCn).ToArray());

            _logger.Debug("User '{User}' profile loaded: {DistinguishedName} (upn={Upn})", user.Name, profile.DistinguishedName, profile.Upn);
            
            //nested groups if configured
            if (clientConfig.LoadActiveDirectoryNestedGroups && clientConfig.ShouldLoadUserGroups())
            {
                LoadAllUserGroups(connAdapter, result.BaseDn, profile.DistinguishedName, profileAttributes);
            }

            return profile;
        }

        private static string[] GetQueryAttributes(ClientConfiguration clientConfig)
        {
            var queryAttributes = new List<string> { "DistinguishedName", "displayName", "mail", "memberOf", "userPrincipalName" };
            if (clientConfig.UseIdentityAttribute)
            {
                queryAttributes.Add(clientConfig.TwoFAIdentityAttribyte);
            }

            //additional attributes for radius response
            queryAttributes.AddRange(clientConfig.GetLdapReplyAttributes());
            queryAttributes.AddRange(clientConfig.PhoneAttributes);

            return queryAttributes.Distinct().ToArray();
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

        private void LoadAllUserGroups(LdapConnectionAdapter connectionAdapter, LdapIdentity baseDn, string dn, LdapAttributes attributes)
        {
            var searchFilter = $"(member:1.2.840.113556.1.4.1941:={dn})";
            var response = connectionAdapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree, false, "DistinguishedName");
            if (response.Entries.Count == 0)
            {
                response = connectionAdapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree, true, "DistinguishedName");
            }

            var groups = response.Entries
                .Cast<SearchResultEntry>()
                .Select(x => LdapIdentity.DnToCn(x.DistinguishedName))
                .Distinct()
                .ToArray();

            attributes.Remove("MemberOf");
            attributes.Add("MemberOf", groups);
        }
    }
}