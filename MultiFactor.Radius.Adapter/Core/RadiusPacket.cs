//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

//MIT License

//Copyright(c) 2017 Verner Fortelius

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace MultiFactor.Radius.Adapter.Core
{
    /// <summary>
    /// This class encapsulates a Radius packet and presents it in a more readable form
    /// </summary>
    public class RadiusPacket : IRadiusPacket
    {
        private readonly RadiusPacketOptions _options = new RadiusPacketOptions();

        public RadiusPacketHeader Header { get; }

        public IDictionary<String, List<Object>> Attributes { get; set; }  = new Dictionary<string, List<object>>();
        public Byte[] RequestAuthenticator
        {
            get;
            internal set;
        }
        /// <summary>
        /// EAP session challenge in progress (ie. wpa2-ent)
        /// </summary>
        public bool IsEapMessageChallenge
        {
            get
            {
                return Header.Code == PacketCode.AccessChallenge && AuthenticationType == AuthenticationType.EAP;
            }
        }
        /// <summary>
        /// ACL and other rules transfer
        /// </summary>
        public bool IsVendorAclRequest
        {
            get
            {
                return UserName?.StartsWith("#ACSACL#-IP") == true;
            }
        }
        /// <summary>
        /// Is our WinLogon
        /// </summary>
        public bool IsWinLogon
        {
            get
            {
                return GetString("mfa-client-name") == "WinLogon";
            }
        }
        /// <summary>
        /// OpenVPN with static-challenge sends pwd and otp in base64 with SCRV1 prefix
        /// https://openvpn.net/community-resources/management-interface/
        /// </summary>
        public bool IsOpenVpnStaticChallenge
        {
            get
            {
                var pwd = UserPassword;
                return pwd != null && pwd.StartsWith("SCRV1:");
            }
        }
        public AuthenticationType AuthenticationType
        {
            get
            {
                if (Attributes.ContainsKey("EAP-Message")) return AuthenticationType.EAP;
                if (Attributes.ContainsKey("User-Password")) return AuthenticationType.PAP;
                if (Attributes.ContainsKey("CHAP-Password")) return AuthenticationType.CHAP;
                if (Attributes.ContainsKey("MS-CHAP-Response")) return AuthenticationType.MSCHAP;
                if (Attributes.ContainsKey("MS-CHAP2-Response")) return AuthenticationType.MSCHAP2;

                return AuthenticationType.Unknown;
            }
        }
        public string UserName => GetString("User-Name");
        internal string UserPassword => GetString("User-Password");
        public string RemoteHostName
        {
            get
            {
                //MS RDGW and RRAS
                return GetString("MS-Client-Machine-Account-Name") ?? GetString("MS-RAS-Client-Name");
            }
        }
        public string CallingStationId => GetCallingStationId();
        public string CalledStationId => GetString("Called-Station-Id");
        public string NasIdentifier => GetString("NAS-Identifier");
        public string State => GetString("State");
        
        public AccountType AccountType
        {
            get
            {
                var attrValue = AcctAuthentic ?? 0;
                return UintToAccountType(attrValue);
            }
        }
        
        public string TryGetUserPassword()
        {
            var password = UserPassword;

            if (IsOpenVpnStaticChallenge)
            {
                try
                {
                    password = password.Split(':')[1].Base64toUtf8();
                }
                catch //invalid packet
                {
                }
            }

            return password;
        }

        /// <summary>
        /// Open VPN static challenge
        /// </summary>
        public string TryGetChallenge()
        {
            var password = UserPassword;

            if (IsOpenVpnStaticChallenge)
            {
                try
                {
                    return password.Split(':')[2].Base64toUtf8();
                }
                catch //invalid packet
                {
                }
            }

            return null;
        }


        public RadiusPacket(RadiusPacketHeader id)
        {
            Header = id ?? throw new ArgumentNullException(nameof(id));
        }

        /// <summary>
        /// Creates a response packet with code, authenticator, identifier and secret from the request packet.
        /// </summary>
        /// <param name="responseCode">New code.</param>
        public IRadiusPacket CreateResponsePacket(PacketCode responseCode)
        {
            var id = RadiusPacketHeader.Create(responseCode, Header.Identifier, Header.SharedSecret);
            var packet = new RadiusPacket(id)
            {
                RequestAuthenticator = Header.Authenticator
            };

            return packet;
        }

        public void Configure(Action<RadiusPacketOptions> configure)
        {
            configure?.Invoke(_options);
        }

        /// <summary>
        /// Gets a single attribute value with name cast to type
        /// Throws an exception if multiple attributes with the same name are found
        /// </summary>
        public T GetAttribute<T>(String name)
        {
            if (Attributes.ContainsKey(name))
            {
                return (T)Attributes[name].Single();
            }

            return default;
        }

        /// <summary>
        /// Gets a single string attribute value
        /// Throws an exception if multiple attributes with the same name are found
        /// </summary>
        public string GetString(string name)
        {
            if (!Attributes.ContainsKey(name))
            {
                return null;
            }

            var value = Attributes[name].Single();
            if (value == null)
            {
                return null;
            }

            switch (value)
            {
                case byte[] _value:
                    return Encoding.UTF8.GetString(_value);

                case string _value:
                    return _value;

                default:
                    return value.ToString();
            }
        }

        public void CopyTo(IRadiusPacket packet)
        {
            packet.Attributes = Attributes;
            packet.Attributes.Remove("Proxy-State"); //should be newer
        }

        public void AddAttribute(String name, String value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(String name, UInt32 value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(String name, IPAddress value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(String name, Byte[] value)
        {
            AddAttributeObject(name, value);
        }

        internal void AddAttributeObject(String name, Object value)
        {
            if (!Attributes.ContainsKey(name))
            {
                Attributes.Add(name, new List<Object>());
            }
            Attributes[name].Add(value);
        }

        public string CreateUniqueKey(IPEndPoint remoteEndpoint)
        {
            var base64Authenticator = Header.Authenticator.Base64();
            return $"{Header.Code.ToString("d")}:{Header.Identifier}:{remoteEndpoint}:{UserName}:{base64Authenticator}";
        }

        private string GetCallingStationId()
        {
            if (!string.IsNullOrWhiteSpace(_options.CallingStationIdAttribute))
            {
                return GetString(_options.CallingStationIdAttribute)
                    ?? GetString("Calling-Station-Id")
                    ?? RemoteHostName;
            }
            return GetString("Calling-Station-Id") ?? RemoteHostName;
        }

        public object Clone()
        {
            var packet = new RadiusPacket(Header)
            {
                Attributes = Attributes,
                RequestAuthenticator = RequestAuthenticator
            };

            return packet;
        }
        
        private uint? AcctAuthentic
        {
            get
            {
                if (Attributes.TryGetValue("Acct-Authentic", out var values))
                {
                    return values.FirstOrDefault() as uint?;
                }

                return null;
            }
        }

        private static AccountType UintToAccountType(uint value)
        {
            switch (value)
            {
                case 1:
                    return AccountType.Domain;
                case 2:
                    return AccountType.Local;
                case 3:
                    return AccountType.Microsoft;
                default:
                    return AccountType.Domain;
            }
        }
    }
    
    public enum AccountType
    {
        Unknown = 0,
        Domain = 1,
        Local = 2,
        Microsoft = 3
    }
}