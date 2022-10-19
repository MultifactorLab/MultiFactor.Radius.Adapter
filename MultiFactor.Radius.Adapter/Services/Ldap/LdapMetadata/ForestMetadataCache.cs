using System;
using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata
{
    /// <summary>
    /// Thread-Safe forest metadata cache.
    /// </summary>
    public class ForestMetadataCache
    {
        private readonly object _locker = new object();
        private readonly Dictionary<string, ForestMetadata> _cache = new Dictionary<string, ForestMetadata>();

        /// <summary>
        /// Returns information about specified domain forest.
        /// </summary>
        /// <param name="clientConfigName">Client configuration frendly name.</param>
        /// <param name="rootDomain">Root domain.</param>
        /// <param name="loader">Forest schema loader that will be executed if specified domain forest info does not exist.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public ForestSchema Get(string clientConfigName, LdapIdentity rootDomain, Func<ForestSchema> loader)
        {
            if (clientConfigName is null) throw new ArgumentNullException(nameof(clientConfigName));
            if (rootDomain is null) throw new ArgumentNullException(nameof(rootDomain));

            lock (_locker)
            {
                ForestSchema schema;

                if (_cache.ContainsKey(clientConfigName))
                {
                    schema = _cache[clientConfigName][rootDomain];
                    if (schema == null)
                    {
                        schema = loader();
                        _cache[clientConfigName].Add(rootDomain, schema);
                    } 
                } 
                else
                {
                    schema = loader();
                    var meta = new ForestMetadata();
                    meta.Add(rootDomain, schema);
                    _cache[clientConfigName] = meta;
                }

                return schema;
            }
        }

        /// <summary>
        /// Returns true if the forest info already exists for the specified client and domain.
        /// </summary>
        /// <param name="clientConfigName">Client configuration frendly name.</param>
        /// <param name="rootDomain">Root domain.</param>
        /// <returns></returns>
        public bool HasSchema(string clientConfigName, LdapIdentity rootDomain)
        {
            lock (_locker)
            {
                return _cache.ContainsKey(clientConfigName) && _cache[clientConfigName].HasSchema(rootDomain);
            }
        }
    }
}
