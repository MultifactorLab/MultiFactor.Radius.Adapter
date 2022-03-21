//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using System.Collections.Generic;
using System.Net;

namespace MultiFactor.Radius.Adapter.Server
{
    public class PendingRequest
    {
        public PendingRequest()
        {
            ResponseCode = PacketCode.AccessReject;
            UserGroups = new List<string>();
        }

        /// <summary>
        /// Client endpoint
        /// </summary>
        public IPEndPoint RemoteEndpoint { get; set; }
        
        /// <summary>
        /// Proxy endpoint (if proxied)
        /// </summary>
        public IPEndPoint ProxyEndpoint { get; set; }

        /// <summary>
        /// Radius request packet
        /// </summary>
        public IRadiusPacket RequestPacket { get; set; }

        /// <summary>
        /// Radius resonse packet (for radius remote first factor)
        /// </summary>
        public IRadiusPacket ResponsePacket { get; set; }
        public PacketCode ResponseCode { get; set; }
        public string State { get; set; }
        public string ReplyMessage { get; set; }
        public string DisplayName { get; set; }
        public string UserPhone { get; set; }
        public string EmailAddress { get; set; }
        public bool Bypass2Fa { get; set; }
        public IList<string> UserGroups { get; set; }
        public bool MustChangePassword { get; set; }

        public IDictionary<string, object> LdapAttrs { get; set; }
    }
}