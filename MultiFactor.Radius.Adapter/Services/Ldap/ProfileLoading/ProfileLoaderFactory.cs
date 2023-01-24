//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.Ldap.UserFinding;
using Serilog;
using System;
using System.DirectoryServices.Protocols;

namespace MultiFactor.Radius.Adapter.Services.Ldap.ProfileLoading
{
    public class ProfileLoaderFactory
    {
        private readonly LdapUserFinderFactory _ldapUserFinderFactory;
        private readonly ILogger _logger;

        public ProfileLoaderFactory(LdapUserFinderFactory ldapUserFinderFactory, ILogger logger)
        {
            _ldapUserFinderFactory = ldapUserFinderFactory ?? throw new ArgumentNullException(nameof(ldapUserFinderFactory));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public ProfileLoader CreateLoader(ClientConfiguration clientConfig, LdapConnection connection)
        {
            if (clientConfig is null) throw new ArgumentNullException(nameof(clientConfig));
            if (connection is null) throw new ArgumentNullException(nameof(connection));       

            return new ProfileLoader(clientConfig, connection, _ldapUserFinderFactory, _logger);
        }
    }
}