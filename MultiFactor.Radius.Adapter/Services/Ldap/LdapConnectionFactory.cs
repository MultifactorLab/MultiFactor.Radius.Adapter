using Serilog;
using System;
using System.DirectoryServices.Protocols;
using System.Net;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class LdapConnectionFactory
    {
        private readonly ILogger _logger;

        public LdapConnectionFactory(ILogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Creates new connection to a ldap domain, binds as a current process user credential using Negotiate auth type and returns it.
        /// </summary>
        /// <param name="domain">LDAP domain</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public LdapConnection CreateAsCurrentProcessUser(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentException($"'{nameof(domain)}' cannot be null or whitespace.", nameof(domain));
            }

            _logger.Debug("Start connection to {Domain}", domain);
            var connection = new LdapConnection(domain);
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.RootDseCache = true;

            _logger.Debug("Start bind to {Domain} as a process user", domain);
            connection.Bind();
            return connection;  
        }

        /// <summary>
        /// Creates new connection to a ldap domain, binds with the specified credential using Negotiate auth type and returns it.
        /// </summary>
        /// <param name="domain">LDAP domain.</param>
        /// <param name="userName">Username.</param>
        /// <param name="password">Password.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public LdapConnection Create(string domain, string userName, string password)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentException($"'{nameof(domain)}' cannot be null or whitespace.", nameof(domain));
            }

            if (string.IsNullOrWhiteSpace(userName))
            {
                throw new ArgumentException($"'{nameof(userName)}' cannot be null or whitespace.", nameof(userName));
            }

            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            _logger.Debug("Start connection to {Domain}", domain);
            var connection = new LdapConnection(domain);
            connection.Credential = new NetworkCredential(userName, password);
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.RootDseCache = true;

            _logger.Debug("Start bind to {Domain} as '{User}'", domain, userName);
            connection.Bind();
            return connection;  
        }

        /// <summary>
        /// Creates new connection to a ldap server, binds with the specified credential using Basic auth type and returns it.
        /// </summary>
        /// <param name="ldapServer">LDAP uri.</param>
        /// <param name="logonName">Logon name.</param>
        /// <param name="password">Password.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public LdapConnection CreateForAdlds(Uri ldapServer, string logonName, string password)
        {
            if (ldapServer is null)
            {
                throw new ArgumentNullException(nameof(ldapServer));
            }

            if (string.IsNullOrWhiteSpace(logonName))
            {
                throw new ArgumentException($"'{nameof(logonName)}' cannot be null or whitespace.", nameof(logonName));
            }

            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            _logger.Debug("Start connection to {Server}", ldapServer.Authority);
            var connection = new LdapConnection(ldapServer.Authority);
            connection.Credential = new NetworkCredential(logonName, password);
            connection.SessionOptions.RootDseCache = true;
            connection.AuthType = AuthType.Basic;

            var isLdaps = ldapServer.Scheme.ToLower() == "ldaps";
            if (isLdaps)
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }

            _logger.Debug("Start bind to {Scheme}://{Server} as '{User}'",
                isLdaps ? "LDAPS" : "LDAP", ldapServer.Authority, logonName);
            connection.Bind();
            return connection;  
        }
    }
}
