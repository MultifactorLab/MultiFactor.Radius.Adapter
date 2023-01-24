using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.Ldap.Connection;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap.UserFinding
{
    public class LdapUserFinder
    {
        private readonly ClientConfiguration _clientConfig;
        private readonly LdapConnection _connection;
        private readonly ForestMetadataCache _metadataCache;
        private readonly ILogger _logger;

        public LdapUserFinder(ClientConfiguration clientConfig, LdapConnection connection, ForestMetadataCache metadataCache, ILogger logger)
        {
            _clientConfig = clientConfig ?? throw new ArgumentNullException(nameof(clientConfig));
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            _metadataCache = metadataCache ?? throw new ArgumentNullException(nameof(metadataCache));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public UserSearchResult FindInForest(LdapIdentity user, LdapIdentity rootDomain, params string[] attributes)
        {
            Func<ForestSchema> loader = () => new ForestSchemaLoader(_clientConfig, _connection, _logger).Load(rootDomain);
            var schema = _metadataCache.Get(_clientConfig.Name, rootDomain, loader);
            var baseDnList = schema.GetBaseDnList(user, rootDomain);
            var searchFilter = $"(&(objectClass=user)({user.TypeName}={user.Name}))";

            var adapter = new LdapConnectionAdapter(_connection, _logger);
            foreach (var baseDn in baseDnList)
            {
                _logger.Debug($"Querying user '{{user:l}}' in {baseDn.Name}", user.Name);

                // only this domain
                var response = adapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree,
                    false,
                    attributes.Distinct().ToArray());

                if (response.Entries.Count != 0)
                {
                    return new UserSearchResult(response.Entries[0], baseDn);
                }

                // with ReferralChasing 
                response = adapter.Query(baseDn.Name, searchFilter, SearchScope.Subtree,
                    true,
                    attributes.Distinct().ToArray());

                if (response.Entries.Count != 0)
                {
                    return new UserSearchResult(response.Entries[0], baseDn);
                }
            }

            _logger.Warning($"User '{{user:l}}' not found in {string.Join(", ", baseDnList.Select(x => $"({x})"))}", user.Name);
            return null;
        }
    }
}
