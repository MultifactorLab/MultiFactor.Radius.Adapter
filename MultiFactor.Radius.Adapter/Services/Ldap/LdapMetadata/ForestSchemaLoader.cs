using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Extensions;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata
{
    public class ForestSchemaLoader
    {
        private readonly ClientConfiguration _clientConfig;
        private readonly ILogger _logger;
        private readonly LdapConnectionAdapter _connectionAdapter;

        private const string CommonNameAttribute = "cn";
        private const string UpnSuffixesAttribute = "uPNSuffixes";
        private const string NetbiosNameAttribute = "netbiosname";

        public ForestSchemaLoader(ClientConfiguration clientConfig, LdapConnection connection, ILogger logger)
        {
            _clientConfig = clientConfig ?? throw new ArgumentNullException(nameof(clientConfig));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _connectionAdapter = new LdapConnectionAdapter(connection, _logger);
        }

        public ForestSchema Load(LdapIdentity root)
        {
            if (root is null) throw new ArgumentNullException(nameof(root));
            _logger.Debug("Loading forest schema from {Root:l}", root);


            var domainNameSuffixes = new Dictionary<string, LdapIdentity>();
            try
            {
                var trustedDomainsResult = _connectionAdapter.Query(
                    "CN=System," + root.Name,
                    "objectClass=trustedDomain",
                    SearchScope.OneLevel,
                    true,
                    CommonNameAttribute);

                var schema = new List<LdapIdentity> { root };
                var trustedDomains = trustedDomainsResult.GetAttributeValuesByName(CommonNameAttribute)
                    .Where(domain => _clientConfig.IsPermittedDomain(domain))
                    .Select(domain => LdapIdentity.FqdnToDn(domain));

                foreach (var domain in trustedDomains)
                {
                    _logger.Debug("Found trusted domain: {Domain:l}", domain);
                    schema.Add(domain);
                }

                foreach (var domain in schema)
                {
                    var domainSuffix = domain.DnToFqdn();
                    if (!domainNameSuffixes.ContainsKey(domainSuffix))
                    {
                        domainNameSuffixes.Add(domainSuffix, domain);
                    }

                    var isChild = schema.Any(parent => domain.IsChildOf(parent));
                    if (!isChild)
                    {
                        try
                        {
                            var uPNSuffixesResult = _connectionAdapter.Query(
                                $"CN=Partitions,CN=Configuration,{domain.Name}",
                                "objectClass=*",
                                SearchScope.Base,
                                true,
                                UpnSuffixesAttribute);
                            List<string> uPNSuffixes = uPNSuffixesResult.GetAttributeValuesByName(UpnSuffixesAttribute);

                            foreach (var suffix in uPNSuffixes.Where(upn => !domainNameSuffixes.ContainsKey(upn)))
                            {
                                domainNameSuffixes.Add(suffix, domain);
                                _logger.Debug("Found alternative UPN suffix {Suffix:l} for domain {Domain}", suffix, domain);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Warning(ex, "Unable to query {Domain:l}", domain);
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Unable to load forest schema");
            }

            return new ForestSchema(domainNameSuffixes);
        }
    }
}
