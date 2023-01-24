//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.Ldap.ProfileLoading;
using Serilog;
using System;
using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory
{
    public class ActiveDirectoryServicesProvider
    {
        private readonly ServiceConfiguration _serviceConfiguration;
        private readonly ProfileLoaderFactory _profileLoaderFactory;
        private readonly ILogger _logger;

        public ActiveDirectoryServicesProvider(ServiceConfiguration serviceConfiguration, ProfileLoaderFactory profileLoaderFactory, ILogger logger)
        {
            _serviceConfiguration = serviceConfiguration ?? throw new ArgumentNullException(nameof(serviceConfiguration));
            _profileLoaderFactory = profileLoaderFactory ?? throw new ArgumentNullException(nameof(profileLoaderFactory));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Returns stanalone AD service instance for each domain/forest with cached schema.
        /// </summary>
        public IDictionary<string, ActiveDirectoryService> GetServices()
        {
            var dict = new Dictionary<string, ActiveDirectoryService>();
            foreach (var domain in _serviceConfiguration.GetAllActiveDirectoryDomains())
            {
                dict.Add(domain, new ActiveDirectoryService(domain, _profileLoaderFactory, _logger));
            }
            return dict;
        }
    }
}