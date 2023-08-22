//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
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

        public PendingRequest(ClientConfiguration clientConfiguration)
        {
            ResponseCode = PacketCode.AccessReject;
            UserGroups = new List<string>();
            ClientConfig = clientConfiguration;
        }

        public readonly ClientConfiguration ClientConfig;

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

        /// <summary>
        /// Gets password from ResponsePacket.UserPassword, skipping OTP (the last 6 characters)
        /// </summary>
        public string GetPassword()
        {
            var passwordAndOtp = RequestPacket.TryGetUserPassword();
            var otpLength = 6;
            var lastIndex = passwordAndOtp.Length - otpLength;
            var password = passwordAndOtp.Substring(0, lastIndex);

            return password;
        }

        /// <summary>
        /// Gets OTP (the last 6 characters) from ResponsePacket.UserPassword, skipping password 
        /// </summary>
        public string GetOtp()
        {
            var passwordAndOtp = RequestPacket.TryGetUserPassword();
            var otpLength = 6;
            var firstIndex = passwordAndOtp.Length - otpLength;
            var otp = passwordAndOtp.Substring(firstIndex, otpLength);

            return otp;
        }
    }
}