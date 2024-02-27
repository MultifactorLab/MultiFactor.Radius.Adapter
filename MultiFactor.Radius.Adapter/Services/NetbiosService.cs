using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Interop;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;

namespace MultiFactor.Radius.Adapter.Services
{
    public class NetbiosService
    {
        private readonly ForestMetadataCache _forestMetadataCache;
        private readonly LdapConnectionFactory _connectionFactory;
        public readonly ILogger _logger;

        public NetbiosService(ForestMetadataCache forestMetadataCache, 
            LdapConnectionFactory connectionFactory,
            ILogger logger)
        {
            _forestMetadataCache = forestMetadataCache;
            _connectionFactory = connectionFactory;
            _logger = logger;
        }

        public LdapIdentity ConvertToUpnUser(ClientConfiguration clientConfig, LdapIdentity user, string domain)
        {
            var upnSuffix = ResolveDomainByNetBios(clientConfig, $"{user.NetBiosName}\\{user.Name}", user.NetBiosName, domain);
            var upnUserName = $"{user.Name}@{upnSuffix}";
            var upnUser = LdapIdentity.ParseUser(upnUserName);
            // sometimes we want to know that this user has logged in using netbios (for example, when loading a profile)
            upnUser.SetNetBiosName(user.NetBiosName);
            return upnUser;
        }

        private string ResolveDomainByNetBios(ClientConfiguration clientConfig, string fullUserName, string netBiosName, string domain)
        {
            _logger.Information($"Trying to resolve domain by netbios {netBiosName}, user:{fullUserName}.");
            try
            {
                using (var nameTranslator = new NameTranslator(domain, _logger))
                {
                    // first try a strict domain resolving method
                    var netBiosDomain = nameTranslator.Translate(fullUserName);
                    if (!string.IsNullOrEmpty(netBiosDomain))
                    {
                        _logger.Information($"Success find {netBiosDomain} by {fullUserName}");
                        return netBiosDomain;
                    }
                }
            }
            catch (Exception e)
            {
                _logger.Warning($"Error during translate netbios name {fullUserName}:\r\n{e.Message}");
            }

            try
            {
                // in case of failure, try to find a suitable suffix
                _logger.Information($"Degradation of the domain resolving method for {fullUserName}");
                using (var connection = _connectionFactory.CreateAsCurrentProcessUser(domain))
                {
                    var dnDomain = LdapIdentity.FqdnToDn(domain);
                    var schema = _forestMetadataCache.Get(
                        clientConfig.Name,
                        dnDomain,
                        () => new ForestSchemaLoader(clientConfig, connection, _logger).Load(dnDomain));
                    var userDomain = schema.FindDomainByNetbiosName(netBiosName);
                    _logger.Information($"Success find {userDomain} by {fullUserName}");
                    return userDomain;
                }
            }
            catch (Exception e)
            {
                _logger.Warning($"Error during translate netbios name {fullUserName}. Domain can't resolving, the request handling stopped.\r\n{e.Message}\r\n");
                throw;
            }
        }
    }
}
