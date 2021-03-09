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
using System.Security.Cryptography;
using System.Text;

namespace MultiFactor.Radius.Adapter.Core
{
    /// <summary>
    /// This class encapsulates a Radius packet and presents it in a more readable form
    /// </summary>
    public class RadiusPacket : IRadiusPacket
    {
        public PacketCode Code
        {
            get;
            internal set;
        }
        public Byte Identifier
        {
            get;
            set;
        }
        public Byte[] Authenticator { get; set; } = new Byte[16];
        public IDictionary<String, List<Object>> Attributes { get; set; }  = new Dictionary<string, List<object>>();
        public Byte[] SharedSecret
        {
            get;
            internal set;
        }
        public Byte[] RequestAuthenticator
        {
            get;
            internal set;
        }

        public bool IsEapMessageChallenge
        {
            get
            {
                return Code == PacketCode.AccessChallenge && AuthenticationType == AuthenticationType.EAP;
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

        internal RadiusPacket()
        {
        }


        /// <summary>
        /// Create a new packet with a random authenticator
        /// </summary>
        /// <param name="code"></param>
        /// <param name="identifier"></param>
        /// <param name="secret"></param>
        /// <param name="authenticator">Set authenticator for testing</param>
        public RadiusPacket(PacketCode code, Byte identifier, String secret)
        {
            Code = code;
            Identifier = identifier;
            SharedSecret = Encoding.UTF8.GetBytes(secret);

            // Generate random authenticator for access request packets
            if (Code == PacketCode.AccessRequest || Code == PacketCode.StatusServer)
            {
                using (var csp = RandomNumberGenerator.Create())
                {
                    csp.GetNonZeroBytes(Authenticator);
                }
            }

            // A Message authenticator is required in status server packets, calculated last
            if (Code == PacketCode.StatusServer)
            {
                AddAttribute("Message-Authenticator", new Byte[16]);
            }
        }


        /// <summary>
        /// Creates a response packet with code, authenticator, identifier and secret from the request packet.
        /// </summary>
        /// <param name="responseCode"></param>
        /// <returns></returns>
        public IRadiusPacket CreateResponsePacket(PacketCode responseCode)
        {
            return new RadiusPacket
            {
                Code = responseCode,
                SharedSecret = SharedSecret,
                Identifier = Identifier,
                RequestAuthenticator = Authenticator
            };
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
            if (Attributes.ContainsKey(name))
            {
                var value = Attributes[name].Single();

                if (value != null)
                {
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
            }

            return null;
        }


        /// <summary>
        /// Gets multiple attribute values with the same name cast to type
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="name"></param>
        /// <returns></returns>
        public List<T> GetAttributes<T>(String name)
        {
            if (Attributes.ContainsKey(name))
            {
                return Attributes[name].Cast<T>().ToList();
            }
            return new List<T>();
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
            var base64Authenticator = Authenticator.Base64();
            return $"{Code.ToString("d")}:{Identifier}:{remoteEndpoint}:{UserName}:{base64Authenticator}";
        }
    }
}