using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.Ldap.UserFinding;
using Serilog;
using System;
using System.DirectoryServices.Protocols;

namespace MultiFactor.Radius.Adapter.Services.Ldap.AttributeLoading
{
    public class AttributeLoaderFactory
    {
        private readonly LdapUserFinderFactory _ldapUserFinderFactory;
        private readonly ILogger _logger;

        public AttributeLoaderFactory(LdapUserFinderFactory ldapUserFinderFactory, ILogger logger)
        {
            _ldapUserFinderFactory = ldapUserFinderFactory ?? throw new ArgumentNullException(nameof(ldapUserFinderFactory));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public AttributeLoader CreateLoader(ClientConfiguration clientConfig, LdapConnection connection)
        {
            if (clientConfig is null) throw new ArgumentNullException(nameof(clientConfig));
            if (connection is null) throw new ArgumentNullException(nameof(connection));

            return new AttributeLoader(clientConfig, connection, _ldapUserFinderFactory, _logger);
        }
    }
}
