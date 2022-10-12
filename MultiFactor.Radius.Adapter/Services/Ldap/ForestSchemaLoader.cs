using MultiFactor.Radius.Adapter.Configuration;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class ForestSchemaLoader
    {
        private readonly ClientConfiguration _clientConfig;
        private readonly ILogger _logger;
        private readonly LdapConnectionAdapter _connectionAdapter;

        public ForestSchemaLoader(ClientConfiguration clientConfig, LdapConnection connection, ILogger logger)
        {
            _clientConfig = clientConfig ?? throw new ArgumentNullException(nameof(clientConfig));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _connectionAdapter = new LdapConnectionAdapter(connection, _logger);
        }

        public ForestSchema Load(LdapIdentity root)
        {
            if (root is null)throw new ArgumentNullException(nameof(root));
            _logger.Debug($"Loading forest schema from {root.Name}");

            var domainNameSuffixes = new Dictionary<string, LdapIdentity>();

            try
            {

                domainNameSuffixes = new Dictionary<string, LdapIdentity>();

                var trustedDomainsResult = _connectionAdapter.Query(
                    "CN=System," + root.Name,
                    "objectClass=trustedDomain",
                    SearchScope.OneLevel,
                    true,
                    "cn");

                var schema = new List<LdapIdentity>{ root };

                for (var i = 0; i < trustedDomainsResult.Entries.Count; i++)
                {
                    var entry = trustedDomainsResult.Entries[i];
                    var attribute = entry.Attributes["cn"];
                    if (attribute != null)
                    {
                        var domain = attribute[0].ToString();
                        if (_clientConfig.IsPermittedDomain(domain))
                        {
                            var trustPartner = LdapIdentity.FqdnToDn(domain);

                            _logger.Debug($"Found trusted domain {trustPartner.Name}");

                            if (!schema.Contains(trustPartner))
                            {
                                schema.Add(trustPartner);
                            }
                        }
                    }
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
                                "CN=Partitions,CN=Configuration," + domain.Name,
                                "objectClass=*",
                                SearchScope.Base,
                                true,
                                "uPNSuffixes");

                            for (var i = 0; i < uPNSuffixesResult.Entries.Count; i++)
                            {
                                var entry = uPNSuffixesResult.Entries[i];
                                var attribute = entry.Attributes["uPNSuffixes"];
                                if (attribute != null)
                                {
                                    for (var j = 0; j < attribute.Count; j++)
                                    {
                                        var suffix = attribute[j].ToString();

                                        if (!domainNameSuffixes.ContainsKey(suffix))
                                        {
                                            domainNameSuffixes.Add(suffix, domain);
                                            _logger.Debug($"Found alternative UPN suffix {suffix} for domain {domain.Name}");
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Warning($"Unable to query {domain.Name}: {ex.Message}");
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
