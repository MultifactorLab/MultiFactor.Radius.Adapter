//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services.Ldap;
using System;
using System.Collections.Generic;
using System.Net;

namespace MultiFactor.Radius.Adapter.Server
{
    public class PendingRequest
    {
        public ClientConfiguration Configuration;

        /// <summary>
        /// Client endpoint
        /// </summary>
        public IPEndPoint RemoteEndpoint { get; private set; }
        
        /// <summary>
        /// Proxy endpoint (if proxied)
        /// </summary>
        public IPEndPoint ProxyEndpoint { get; private set; }

        /// <summary>
        /// Radius request packet
        /// </summary>
        public IRadiusPacket RequestPacket { get; private set; }

        /// <summary>
        /// Radius resonse packet (for radius remote first factor)
        /// </summary>
        public IRadiusPacket ResponsePacket { get; set; }
        public PacketCode ResponseCode { get; set; }
        public string State { get; set; }
        public string ReplyMessage { get; set; }

        public string UserName { get; private set; }
        public bool Bypass2Fa { get; set; }
        public IList<string> UserGroups { get; set; }

        public bool MustChangePassword { get; private set; }
        public string MustChangePasswordDomain { get; private set; }

        public LdapProfile Profile { get; private set; }

        /// <summary>
        /// Should use for 2FA request to MFA API.
        /// </summary>
        public string SecondFactorIdentity => Configuration.UseIdentityAttribute ? Profile.LdapAttrs.GetValue(Configuration.TwoFAIdentityAttribyte) : UserName;

        public UserPassphrase Passphrase { get; private set; }

        private PendingRequest(ClientConfiguration clientConfiguration)
        {
            ResponseCode = PacketCode.AccessReject;
            Configuration = clientConfiguration;
            Profile = LdapProfile.Empty(clientConfiguration);
        }

        public static PendingRequest Create(ClientConfiguration clientConfiguration, IPEndPoint remoteEndpoint, IPEndPoint proxyEndpoint, IRadiusPacket packet)
        {
            if (clientConfiguration is null)
            {
                throw new ArgumentNullException(nameof(clientConfiguration));
            }

            return new PendingRequest(clientConfiguration)
            {
                RemoteEndpoint = remoteEndpoint ?? throw new ArgumentNullException(nameof(remoteEndpoint)),
                ProxyEndpoint = proxyEndpoint,
                RequestPacket = packet ?? throw new ArgumentNullException(nameof(packet)),
                Passphrase = UserPassphrase.Parse(packet, clientConfiguration.PreAuthnMode),
                UserName = packet.UserName
            };
        }

        public void UpdateProfile(LdapProfile profile)
        {
            Profile = profile;
        }

        public void UpdateUserName(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException($"'{nameof(username)}' cannot be null or whitespace.", nameof(username));
            }

            UserName = username;
        }

        public void SetMustChangePassword(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentException($"'{nameof(domain)}' cannot be null or whitespace.", nameof(domain));
            }

            MustChangePassword = true;
            MustChangePasswordDomain = domain;
        }
    }
}