//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using System;
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
        /// User group condition
        /// </summary>
        public string UserGroupCondition { get; set; }

        /// <summary>
        /// User name condition
        /// </summary>
        public string UserNameCondition { get; set; }

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
                return request.LdapAttrs?[LdapAttributeName] != null;
            }

            //if matched user name condition
            if (!string.IsNullOrEmpty(UserNameCondition))
            {
                var userName = request.RequestPacket.UserName;
                var isCanonical = Utils.IsCanicalUserName(UserNameCondition);
                if (isCanonical)
                {
                    userName = Utils.CanonicalizeUserName(userName);
                }

                return string.Compare(userName, UserNameCondition, StringComparison.InvariantCultureIgnoreCase) == 0;
            }

            //if matched user group condition
            if (!string.IsNullOrEmpty(UserGroupCondition))
            {
                var isInGroup = request
                    .UserGroups
                    .Any(g => string.Compare(g, UserGroupCondition, StringComparison.InvariantCultureIgnoreCase) == 0);

                return isInGroup;
            }

            return true; //without conditions
        }

        public object GetValue(PendingRequest request)
        {
            if (FromLdap)
            {
                return request.LdapAttrs[LdapAttributeName];
            }

            return Value;
        }

        private void ParseConditionClause(string clause)
        {
            var parts = clause.Split(new[] { '=' }, StringSplitOptions.RemoveEmptyEntries);

            switch (parts[0])
            {
                case "UserGroup":
                    UserGroupCondition = parts[1];
                    break;
                case "UserName":
                    UserNameCondition = parts[1];
                    break;
                default:
                    throw new Exception($"Unknown condition '{clause}'");
            }
        }
    }
}
