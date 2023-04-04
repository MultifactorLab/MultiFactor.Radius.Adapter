//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Server
{
    /// <summary>
    /// Radius Access-Accept message extra element
    /// </summary>
    public class RadiusReplyAttributeValue
    {
        public bool FromLdap { get; set; }

        /// <summary>
        /// Const value with optional condition
        /// </summary>
        public RadiusReplyAttributeValue(object value, string conditionClause)
        {
            Value = value;
            if (!string.IsNullOrEmpty(conditionClause))
            {
                ParseConditionClause(conditionClause);
            }
        }

        /// <summary>
        /// Proxy value from LDAP attr
        /// </summary>
        public RadiusReplyAttributeValue(string ldapAttributeName)
        {
            if (string.IsNullOrEmpty(ldapAttributeName))
            {
                throw new ArgumentNullException(nameof(ldapAttributeName));
            }

            LdapAttributeName = ldapAttributeName;
            FromLdap = true;
        }   

        /// <summary>
        /// Attribute Value
        /// </summary>
        public object Value { get; }

        /// <summary>
        /// Ldap attr name to proxy value from
        /// </summary>
        public string LdapAttributeName { get; set; }

        /// <summary>
        /// Is list of all user groups attribute
        /// </summary>
        public bool IsMemberOf
        {
            get
            {
                return LdapAttributeName?.ToLower() == "memberof";
            }
        }

        /// <summary>
        /// User group condition
        /// </summary>
        public List<string> UserGroupCondition { get; set; }

        /// <summary>
        /// User name condition
        /// </summary>
        public List<string> UserNameCondition { get; set; }

        /// <summary>
        /// Is match condition
        /// </summary>
        public bool IsMatch(PendingRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            //if exist ldap attr value
            if (FromLdap)
            {
                //if list of all groups
                if (IsMemberOf)
                {
                    return request.UserGroups?.Count > 0;
                }

                //just attribute
                return request.LdapAttrs?[LdapAttributeName] != null;
            }

            //if matched user name condition
            if (UserNameCondition != null && UserNameCondition.Any())
            {
                var userName = request.UserName;
                var canonicalUserName = Utils.CanonicalizeUserName(userName);
                Func<string, bool> comapareLogic = (string conditionName) =>
                {
                    var toMatch = Utils.IsCanicalUserName(conditionName)
                            ? canonicalUserName
                            : userName;
                    return string.Compare(toMatch, conditionName,
                        StringComparison.InvariantCultureIgnoreCase) == 0;
                };
                return UserNameCondition.Any(comapareLogic);
            }

            //if matched user group condition
            if (UserGroupCondition != null && UserGroupCondition.Any())
            {
                return UserGroupCondition.Intersect(
                     request.UserGroups,
                     StringComparer.OrdinalIgnoreCase
                ).Any();
            }

            return true; //without conditions
        }

        public object[] GetValues(PendingRequest request)
        {
            if (IsMemberOf)
            {
                return request.UserGroups.ToArray();
            }

            if (FromLdap)
            {
                return new object[] { request.LdapAttrs[LdapAttributeName] };
            }

            return new object[] { Value };
        }

        private void ParseConditionClause(string clause)
        {
            var parts = clause.Split(new[] { '=' }, StringSplitOptions.RemoveEmptyEntries);

            switch (parts[0])
            {
                case "UserGroup":
                    UserGroupCondition = parts[1].Split(new[] { ';' },
                        StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => x.Trim())
                        .ToList();
                    break;
                case "UserName":
                    UserNameCondition = parts[1].Split(new[] { ';' },
                        StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => x.Trim())
                        .ToList();
                    break;
                default:
                    throw new Exception($"Unknown condition '{clause}'");
            }
        }
    }
}
