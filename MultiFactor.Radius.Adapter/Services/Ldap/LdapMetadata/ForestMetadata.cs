using System;
using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata
{
    public class ForestMetadata
    {
        private readonly Dictionary<string, ForestSchema> _forests = new Dictionary<string, ForestSchema>();

        /// <summary>
        /// Returns information about forest of specifiet root domain.
        /// </summary>
        /// <param name="rootDomain">Root domain.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public ForestSchema this[LdapIdentity rootDomain]
        {
            get
            {
                if (rootDomain is null) throw new ArgumentNullException(nameof(rootDomain));
                if (_forests.ContainsKey(rootDomain.Name)) return _forests[rootDomain.Name];
                return null;
            }
        }

        /// <summary>
        /// Adds forest information of specified domain.
        /// </summary>
        /// <param name="rootDomain">Root domain.</param>
        public void Add(LdapIdentity rootDomain, ForestSchema schema)
        {
            if (!_forests.ContainsKey(rootDomain.Name))
            {
                _forests[rootDomain.Name] = schema;
            }
        }

        /// <summary>
        /// Returns true if information about specified domain forest already exists in the current metadata object.
        /// </summary>
        /// <param name="rootDomain">Root domain.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public bool HasSchema(LdapIdentity rootDomain)
        {
            if (rootDomain is null) throw new ArgumentNullException(nameof(rootDomain));
            return _forests.ContainsKey(rootDomain.Name);
        }
    }
}
