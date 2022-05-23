//Copyright(c) 2022 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace MultiFactor.Radius.Adapter.Configuration
{
    public class ClientConfiguration
    {
        public ClientConfiguration()
        {
            BypassSecondFactorWhenApiUnreachable = true; //by default
            LoadActiveDirectoryNestedGroups = true;
            ActiveDirectoryGroup = new string[0];
            ActiveDirectory2FaGroup = new string[0];
            PhoneAttributes = new List<string>();
            UserNameTransformRules = new List<UserNameTransformRulesElement>();
        }

        /// <summary>
        /// Friendly client name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Shared secret between this service and Radius client
        /// </summary>
        public string RadiusSharedSecret { get; set; }

        /// <summary>
        /// Custom encoding name for pap password (eg windows-1251)
        /// </summary>
        public string RadiusPapEncoding { get; set; }

        /// <summary>
        /// Where to handle first factor (UserName and Password)
        /// </summary>
        public AuthenticationSource FirstFactorAuthenticationSource { get; set; }

        /// <summary>
        /// Bypass second factor when MultiFactor API is unreachable
        /// </summary>
        public bool BypassSecondFactorWhenApiUnreachable { get; set; }

        /// <summary>
        /// Bypass second factor within specified minutes period for same client-machine/user-name
        /// </summary>
        public int? BypassSecondFactorPeriod { get; set; }


        #region ActiveDirectory Authentication settings

        /// <summary>
        /// Active Directory Domain
        /// </summary>
        public string ActiveDirectoryDomain { get; set; }

        /// <summary>
        /// Only members of this group allowed to access (Optional)
        /// </summary>
        public string[] ActiveDirectoryGroup { get; set; }

        /// <summary>
        /// Only members of this group required to pass 2fa to access (Optional)
        /// </summary>
        public string[] ActiveDirectory2FaGroup { get; set; }

        /// <summary>
        /// AD attribute name(s) where to search phone number
        /// </summary>
        public IList<string> PhoneAttributes { get; set; }

        /// <summary>
        /// Load nested groups (may be slow)
        /// </summary>
        public bool LoadActiveDirectoryNestedGroups { get; set; }

        /// <summary>
        /// Load user profile from AD and check group membership and 
        /// </summary>
        public bool CheckMembership
        {
            get
            {
                return ActiveDirectoryDomain != null &&
                    (ActiveDirectoryGroup != null ||
                    ActiveDirectory2FaGroup != null ||
                    PhoneAttributes.Any() ||
                    RadiusReplyAttributes
                        .Values
                        .SelectMany(attr => attr)
                        .Any(attr => attr.FromLdap || attr.IsMemberOf || attr.UserGroupCondition != null));
            }
        }

        /// <summary>
        /// Only UPN user name format permitted
        /// </summary>
        public bool RequiresUpn { get; set; }

        /// <summary>
        /// Use only these domains within forest(s)
        /// </summary>
        public IList<string> IncludedDomains { get; set; }

        /// <summary>
        /// Use all but not these domains within forest(s)
        /// </summary>
        public IList<string> ExcludedDomains { get; set; }

        /// <summary>
        /// Check if any included domains or exclude domains specified and contains required domain
        /// </summary>
        public bool IsPermittedDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain)) throw new ArgumentNullException(nameof(domain));

            if (IncludedDomains?.Count > 0)
            {
                return IncludedDomains.Any(included => included.ToLower() == domain.ToLower());
            }
            if (ExcludedDomains?.Count > 0)
            {
                return !ExcludedDomains.Any(excluded => excluded.ToLower() == domain.ToLower());
            }

            return true;
        }

        #endregion

        #region RADIUS Authentication settings

        /// <summary>
        /// This service RADIUS UDP Client endpoint
        /// </summary>
        public IPEndPoint ServiceClientEndpoint { get; set; }
        /// <summary>
        /// Network Policy Service RADIUS UDP Server endpoint
        /// </summary>
        public IPEndPoint NpsServerEndpoint { get; set; }

        #endregion

        #region General LDAP settings

        public Uri LdapUrl { get; set; }

        #endregion


        /// <summary>
        /// Multifactor API key
        /// </summary>
        public string MultifactorApiKey { get; set; }
        /// <summary>
        /// Multifactor API secret
        /// </summary>
        public string MultiFactorApiSecret { get; set; }


        /// <summary>
        /// Custom RADIUS reply attributes
        /// </summary>
        public IDictionary<string, List<RadiusReplyAttributeValue>> RadiusReplyAttributes { get; set; }

        /// <summary>
        /// Username transform rules
        /// </summary>
        public IList<UserNameTransformRulesElement> UserNameTransformRules { get; set; }

        public IList<string> GetLdapReplyAttributes()
        {
            return RadiusReplyAttributes
                .Values
                .SelectMany(attr => attr)
                .Where(attr => attr.FromLdap)
                .Select(attr => attr.LdapAttributeName)
                .ToList();
        }

        public bool ShouldLoadUserGroups()
        {
            return
                ActiveDirectoryGroup != null ||
                ActiveDirectory2FaGroup != null ||
                RadiusReplyAttributes
                    .Values
                    .SelectMany(attr => attr)
                    .Any(attr => attr.IsMemberOf || attr.UserGroupCondition != null);
        }
    }
}
