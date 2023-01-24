using MultiFactor.Radius.Adapter.Core;
using System;
using System.DirectoryServices.Protocols;
using System.Net;

namespace MultiFactor.Radius.Adapter.Services.Ldap.Connection
{
    public static class LdapConnectionFactory
    {
        /// <summary>
        /// Creates connection using Microsoft Negotiate authentication. Credential will be getted from the current process.
        /// </summary>
        /// <param name="server">Server to connect.</param>
        /// <returns>Connection object.</returns>
        public static LdapConnection CreateConnection(string server)
        {
            var connection = new LdapConnection(server);

            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.RootDseCache = true;
            if (GlobalState.RunOptions.HasOption(Core.ApplicationOptions.RunOptionName.Usr) 
                && GlobalState.RunOptions.HasOption(Core.ApplicationOptions.RunOptionName.Pwd))
            {
                var usr = GlobalState.RunOptions.GetOption(Core.ApplicationOptions.RunOptionName.Usr);
                var pwd = GlobalState.RunOptions.GetOption(Core.ApplicationOptions.RunOptionName.Pwd);
                connection.Credential = new NetworkCredential(usr.Value, pwd.Value);
            }
            connection.Bind();

            return connection;
        }

        /// <summary>
        /// Creates connection using Microsoft Negotiate authentication with the specified credential.
        /// </summary>
        /// <param name="server">Server to connect.</param>
        /// <param name="userName">Username.</param>
        /// <param name="password">Password.</param>
        /// <returns>Connection object.</returns>
        public static LdapConnection CreateConnection(string server, string userName, string password)
        {
            var connection = new LdapConnection(server)
            {
                Credential = new NetworkCredential(userName, password)
            };

            connection.SessionOptions.RootDseCache = true;
            connection.SessionOptions.ProtocolVersion = 3;
            connection.Bind();

            return connection;
        }
        
        /// <summary>
        /// Creates connection using Basic authentication withe the specified LDAP address and credential.
        /// </summary>
        /// <param name="ldapUrl">LDAP server address.</param>
        /// <param name="userName">Username.</param>
        /// <param name="password">Password.</param>
        /// <returns>Connection object.</returns>
        public static LdapConnection CreateConnection(Uri ldapUrl, string userName, string password)
        {
            var connection = new LdapConnection(ldapUrl.Authority)
            {
                Credential = new NetworkCredential(userName, password)
            };

            connection.SessionOptions.RootDseCache = true;
            connection.AuthType = AuthType.Basic;

            if (ldapUrl.Scheme.ToLower() == "ldaps")
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }

            connection.Bind();

            return connection;
        }
    }
}
