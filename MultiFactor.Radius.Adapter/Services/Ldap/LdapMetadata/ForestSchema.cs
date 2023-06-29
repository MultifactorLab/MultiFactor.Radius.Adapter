using MultiFactor.Radius.Adapter.Services.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata
{
    /// <summary>
    /// Information about domain controller forest.
    /// </summary>
    public class ForestSchema
    {
        private readonly IReadOnlyDictionary<string, LdapIdentity> _domainNameSuffixes =
            new Dictionary<string, LdapIdentity>();

        public IReadOnlyDictionary<string, LdapIdentity> DomainNameSuffixes => _domainNameSuffixes;

        public ForestSchema(IReadOnlyDictionary<string, LdapIdentity> domainNameSuffixes)
        {
            _domainNameSuffixes = domainNameSuffixes ?? throw new ArgumentNullException(nameof(domainNameSuffixes));
        }

        public LdapIdentity GetMostRelevanteDomain(LdapIdentity user, LdapIdentity defaultDomain)
        {
            if (user is null) throw new ArgumentNullException(nameof(user));
            if (defaultDomain is null) throw new ArgumentNullException(nameof(defaultDomain));

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


        public List<LdapIdentity> FindDomainByNetbiosName(string netbiosName)
        {
            return _domainNameSuffixes.Values
                .Where(x => string.Equals(x.NetBiosName, netbiosName, StringComparison.OrdinalIgnoreCase))
                .Distinct(new LdapDomainEqualityComparer())
                .ToList();
        }
    }
}
