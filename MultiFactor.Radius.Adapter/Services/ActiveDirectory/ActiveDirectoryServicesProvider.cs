//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory
{
    public class ActiveDirectoryServicesProvider
    {
        private readonly IServiceProvider _provider;

        public ActiveDirectoryServicesProvider(IServiceProvider provider)
        {
            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        }

        /// <summary>
        /// Returns stanalone AD service instance for each domain/forest with cached schema.
        /// </summary>
        public IDictionary<string, ActiveDirectoryService> GetServices()
        {
            var dict = new Dictionary<string, ActiveDirectoryService>();
            var config = _provider.GetRequiredService<ServiceConfiguration>();
            foreach (var domain in config.GetAllActiveDirectoryDomains())
            {
                dict.Add(domain, new ActiveDirectoryService(
                    domain,
                    _provider.GetRequiredService<ForestMetadataCache>(),
                    _provider.GetRequiredService<NetbiosService>(),
                    _provider.GetRequiredService<LdapConnectionFactory>(),
                    _provider.GetRequiredService<ILogger>())
                    );
            }
            return dict;
        }
    }
}