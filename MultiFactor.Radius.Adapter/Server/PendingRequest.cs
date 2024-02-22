//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
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

        public string UserName { get; set; }
        public string Upn { get; set; }
        public string DisplayName { get; set; }
        public string UserPhone { get; set; }
        public string EmailAddress { get; set; }
        public bool Bypass2Fa { get; set; }
        public IList<string> UserGroups { get; set; }
        public bool MustChangePassword { get; set; }
        public string MustChangePasswordDomain { get; set; }

        public IDictionary<string, object> LdapAttrs { get; set; }

        public UserPassphrase Passphrase { get; private set; }

        private PendingRequest(ClientConfiguration clientConfiguration)
        {
            ResponseCode = PacketCode.AccessReject;
            UserGroups = new List<string>();
            Configuration = clientConfiguration;
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

        public void ModifyRadiusAttribute(string attribute, string value) 
        {
            if (string.IsNullOrWhiteSpace(attribute))
            {
                throw new ArgumentException($"'{nameof(attribute)}' cannot be null or whitespace.", nameof(attribute));
            }

            ValidateAttribute(attribute, value);
        }

        private void ValidateAttribute(string attribute, string value)
        {

        }
    }
}