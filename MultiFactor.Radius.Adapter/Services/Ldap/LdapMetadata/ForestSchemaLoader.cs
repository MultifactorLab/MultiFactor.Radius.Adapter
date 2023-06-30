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
            _logger.Debug($"Loading forest schema from {root.Name}");


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
                _logger.Debug($"Found trusted domains:\r\n{string.Join(";", trustedDomains)}");
                schema.AddRange(trustedDomains);

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
                                UpnSuffixesAttribute);
                            List<string> uPNSuffixes = uPNSuffixesResult.GetAttributeValuesByName(UpnSuffixesAttribute);

                            foreach (var suffix in uPNSuffixes.Where(upn => !domainNameSuffixes.ContainsKey(upn)))
                            {
                                domainNameSuffixes.Add(suffix, domain);
                                _logger.Debug($"Found alternative UPN suffix {suffix} for domain {domain.Name}");
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

        private void InitializeNetbiosNames(List<LdapIdentity> schema)
        {
            foreach (var domain in schema)
            {
                var netbiosNameResponse = _connectionAdapter.Query(
                    "CN=Partitions,CN=Configuration," + domain.Name,
                    "(&(objectcategory=crossref)(netbiosname=*))",
                    SearchScope.OneLevel,
                    true, // TODO
                    NetbiosNameAttribute);
                List<string> netbiosNames = netbiosNameResponse.GetAttributeValuesByName(NetbiosNameAttribute);

                if (netbiosNames.Count == 1)
                {
                    _logger.Information($"Find netbiosname {netbiosNames[0]} for domain {domain}");
                    domain.SetNetBiosName(netbiosNames[0]);
                    continue;
                }
                _logger.Warning($"Unexpected netbiosname(s) for domain {domain}:{string.Join(";", netbiosNames)}");
            }
        }
    }
}
