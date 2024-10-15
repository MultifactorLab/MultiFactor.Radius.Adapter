//Copyright(c) 2022 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration.Features.PreAuthnModeFeature;
using MultiFactor.Radius.Adapter.Configuration.Features.PrivacyModeFeature;
using MultiFactor.Radius.Adapter.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace MultiFactor.Radius.Adapter.Configuration
{
    /// <summary>
    /// Dedicated client configuration (affects the connected client only).
    /// </summary>
    public class ClientConfiguration
    {
        public ClientConfiguration()
        {
            BypassSecondFactorWhenApiUnreachable = true; //by default
            LoadActiveDirectoryNestedGroups = true;
            ActiveDirectoryGroup = new string[0];
            ActiveDirectory2FaGroup = new string[0];
            ActiveDirectory2FaBypassGroup = new string[0];
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

        public PrivacyModeDescriptor PrivacyMode { get; set; }

        public string TwoFAIdentityAttribyte { get; set; }

        public PreAuthnModeDescriptor PreAuthnMode { get; set; }

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
        /// Members of this group should not pass 2fa to access (Optional)
        /// </summary>
        public string[] ActiveDirectory2FaBypassGroup { get; set; }

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
                    (ActiveDirectoryGroup.Any() ||
                    ActiveDirectory2FaGroup.Any() ||
                    ActiveDirectory2FaBypassGroup.Any() ||
                    PhoneAttributes.Any() ||
                    RadiusReplyAttributes
                        .Values
                        .SelectMany(attr => attr)
                        .Any(attr => attr.FromLdap || attr.IsMemberOf || attr.UserGroupCondition != null));
            }
        }

        public string[] SplittedActiveDirectoryDomains =>
            (ActiveDirectoryDomain ?? string.Empty).Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Distinct()
            .ToArray();

        /// <summary>
        /// Only UPN user name format permitted
        /// </summary>
        public bool RequiresUpn { get; set; }

        //Lookup for some attribute and use it for 2fa instead of uid
        public bool UseIdentityAttribute => !string.IsNullOrEmpty(TwoFAIdentityAttribyte);

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
                ActiveDirectoryGroup.Any() ||
                ActiveDirectory2FaGroup.Any() ||
                RadiusReplyAttributes
                    .Values
                    .SelectMany(attr => attr)
                    .Any(attr => attr.IsMemberOf || attr.UserGroupCondition != null);
        }

        /// <summary>
        /// Groups to assign to the registered user.Specified groups will be assigned to a new user.
        /// Syntax: group names (from your Management Portal) separated by semicolons.
        /// <para>
        /// Example: group1;Group Name Two;
        /// </para>
        /// </summary>
        public string SignUpGroups { get; set; }

        public AuthenticatedClientCacheConfig AuthenticationCacheLifetime { get; internal set; }

        public string CallingStationIdVendorAttribute { get; internal set; }

        /// <summary>
        /// Overrides the root-level config.
        /// </summary>
        public RandomWaiterConfig InvalidCredentialDelay { get; internal set; }
        
        /// <summary>
        /// Ldap connection timeout
        /// </summary>
        public TimeSpan LdapBindTimeout { get; set; } = new TimeSpan(0, 0, 30);
    }
}
