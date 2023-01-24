using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.Ldap.UserFinding;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap.AttributeLoading
{
    public class AttributeLoader
    {
        private readonly ClientConfiguration _clientConfig;
        private readonly LdapConnection _connection;
        private readonly LdapUserFinderFactory _ldapUserFinderFactory;
        private readonly ILogger _logger;

        public AttributeLoader(ClientConfiguration clientConfig, LdapConnection connection, LdapUserFinderFactory ldapUserFinderFactory, ILogger logger)
        {
            _clientConfig = clientConfig ?? throw new ArgumentNullException(nameof(clientConfig));
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            _ldapUserFinderFactory = ldapUserFinderFactory ?? throw new ArgumentNullException(nameof(ldapUserFinderFactory));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public LoadedAttributes LoadAttributes(LdapIdentity user, LdapIdentity rootDomain, params string[] attrs)
        {
            if (!attrs.Any())
            {
                _logger.Warning("No such attribute to loading. Empty result will be returned.");
                return LoadedAttributes.Empty;
            }

            _logger.Debug("Loading attributes for user '{user}' at '{domain}': {attrs:l}",
                user,
                rootDomain,
                string.Join(", ", attrs));
            var finder = _ldapUserFinderFactory.CreateFinder(_clientConfig, _connection);
            var result = finder.FindInForest(user, rootDomain, attrs);
            if (result == null)
            {
                _logger.Warning("Unable to load attributes becuse user '{u:l}' not found at '{domain}'. Not loaded attributes: {attrs:l}",
                    user,
                    rootDomain,
                    string.Join(", ", attrs));
                return LoadedAttributes.Empty;
            }

            var attributes = new Dictionary<string, string[]>();
            foreach (var a in attrs)
            {
                var loadedAttributeValues = result.Entry.Attributes[a];
                if (loadedAttributeValues == null || loadedAttributeValues.Capacity == 0) continue;
                attributes[a] = loadedAttributeValues.GetValues(typeof(string)).Select(x => x.ToString()).ToArray();
            }

            var notLoaded = attrs.Where(x => !attributes.ContainsKey(x)).ToArray();
            if (notLoaded.Length != 0)
            {
                _logger.Warning("Not all requested attributes are loaded. Not loaded attributes:", string.Join(", ", notLoaded));
            }

            return new LoadedAttributes(attributes);
        }
    }
}
