using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.DirectoryServices.Protocols;

namespace MultiFactor.Radius.Adapter.Services.Ldap.UserFinding
{
    public class LdapUserFinderFactory
    {
        private readonly ForestMetadataCache _metadataCache;
        private readonly ILogger _logger;

        public LdapUserFinderFactory(ForestMetadataCache metadataCache, ILogger logger)
        {
            _metadataCache = metadataCache ?? throw new ArgumentNullException(nameof(metadataCache));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public LdapUserFinder CreateFinder(ClientConfiguration clientConfig, LdapConnection connection)
        {
            if (clientConfig is null) throw new ArgumentNullException(nameof(clientConfig));
            if (connection is null) throw new ArgumentNullException(nameof(connection));

            return new LdapUserFinder(clientConfig, connection, _metadataCache, _logger);
        }
    }
}
