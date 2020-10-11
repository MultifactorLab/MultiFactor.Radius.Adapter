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

using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace MultiFactor.Radius.Adapter.Core
{
    public class RadiusPacketParser : IRadiusPacketParser
    {
        private readonly ILogger _logger;
        private readonly IRadiusDictionary _radiusDictionary;


        /// <summary>
        /// RadiusPacketParser
        /// </summary>
        /// <param name="logger"></param>
        public RadiusPacketParser(ILogger logger, IRadiusDictionary radiusDictionary)
        {
            _logger = logger;
            _radiusDictionary = radiusDictionary;
        }


        /// <summary>
        /// Parses packet bytes and returns an IRadiusPacket
        /// </summary>
        /// <param name="packetBytes"></param>
        /// <param name="dictionary"></param>
        /// <param name="sharedSecret"></param>
        public IRadiusPacket Parse(Byte[] packetBytes, Byte[] sharedSecret, byte[] requestAuthenticator = null)
        {
            var packetLength = BitConverter.ToUInt16(packetBytes.Skip(2).Take(2).Reverse().ToArray(), 0);
            if (packetBytes.Length != packetLength)
            {
                throw new InvalidOperationException($"Packet length does not match, expected: {packetLength}, actual: {packetBytes.Length}");
            }

            var packet = new RadiusPacket
            {
                SharedSecret = sharedSecret,
                Identifier = packetBytes[1],
                Code = (PacketCode)packetBytes[0],
            };

            Buffer.BlockCopy(packetBytes, 4, packet.Authenticator, 0, 16);

            if (packet.Code == PacketCode.AccountingRequest || packet.Code == PacketCode.DisconnectRequest)
            {
                if (!packet.Authenticator.SequenceEqual(CalculateRequestAuthenticator(packet.SharedSecret, packetBytes)))
                {
                    throw new InvalidOperationException("Invalid request authenticator in packet {packet.Identifier}, check secret?");
                }
            }

            // The rest are attribute value pairs
            var position = 20;
            var messageAuthenticatorPosition = 0;
            while (position < packetBytes.Length)
            {
                var typecode = packetBytes[position];
                var length = packetBytes[position + 1];

                if (position + length > packetLength)
                {
                    throw new ArgumentOutOfRangeException("Go home roamserver, youre drunk");
                }
                var contentBytes = new Byte[length - 2];
                Buffer.BlockCopy(packetBytes, position + 2, contentBytes, 0, length - 2);

                try
                {
                    if (typecode == 26) // VSA
                    {
                        var vsa = new VendorSpecificAttribute(contentBytes);
                        var vendorAttributeDefinition = _radiusDictionary.GetVendorAttribute(vsa.VendorId, vsa.VendorCode);
                        if (vendorAttributeDefinition == null)
                        {
                            _logger.Debug($"Unknown vsa: {vsa.VendorId}:{vsa.VendorCode}");
                        }
                        else
                        {
                            try
                            {
                                var content = ParseContentBytes(vsa.Value, vendorAttributeDefinition.Type, typecode, packet.Authenticator, packet.SharedSecret);
                                packet.AddAttributeObject(vendorAttributeDefinition.Name, content);
                            }
                            catch (Exception ex)
                            {
                                _logger.Error(ex, $"Something went wrong with vsa {vendorAttributeDefinition.Name}");
                            }
                        }
                    }
                    else
                    {
                        var attributeDefinition = _radiusDictionary.GetAttribute(typecode);
                        if (attributeDefinition.Code == 80)
                        {
                            messageAuthenticatorPosition = position;
                        }
                        try
                        {
                            var content = ParseContentBytes(contentBytes, attributeDefinition.Type, typecode, packet.Authenticator, packet.SharedSecret);
                            packet.AddAttributeObject(attributeDefinition.Name, content);
                        }
                        catch (Exception ex)
                        {
                            _logger.Error(ex, $"Something went wrong with {attributeDefinition.Name}");
                            _logger.Debug($"Attribute bytes: {contentBytes.ToHexString()}");
                        }
                    }
                }
                catch (KeyNotFoundException)
                {
                    _logger.Warning($"Attribute {typecode} not found in dictionary");
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, $"Something went wrong parsing attribute {typecode}");
                }

                position += length;
            }

            if (messageAuthenticatorPosition != 0)
            {
                var messageAuthenticator = packet.GetAttribute<Byte[]>("Message-Authenticator");
                var temp = new Byte[16];
                var tempPacket = new Byte[packetBytes.Length];
                packetBytes.CopyTo(tempPacket, 0);
                Buffer.BlockCopy(temp, 0, tempPacket, messageAuthenticatorPosition + 2, 16);
                var calculatedMessageAuthenticator = CalculateMessageAuthenticator(tempPacket, sharedSecret, requestAuthenticator);
                if (!calculatedMessageAuthenticator.SequenceEqual(messageAuthenticator))
                {
                    throw new InvalidOperationException($"Invalid Message-Authenticator in packet {packet.Identifier}");
                }
            }

            packet.RequestAuthenticator = requestAuthenticator;

            return packet;
        }


        /// <summary>
        /// Parses the content and returns an object of proper type
        /// </summary>
        /// <param name="contentBytes"></param>
        /// <param name="type"></param>
        /// <param name="code"></param>
        /// <param name="authenticator"></param>
        /// <param name="sharedSecret"></param>
        /// <returns></returns>
        private Object ParseContentBytes(Byte[] contentBytes, String type, UInt32 code, Byte[] authenticator, Byte[] sharedSecret)
        {
            switch (type)
            {
                case DictionaryAttribute.TYPE_STRING:
                case DictionaryAttribute.TYPE_TAGGED_STRING:
                    return Encoding.UTF8.GetString(contentBytes);

                case DictionaryAttribute.TYPE_OCTET:
                    // If this is a password attribute it must be decrypted
                    if (code == 2)
                    {
                        return RadiusPassword.Decrypt(sharedSecret, authenticator, contentBytes);
                    }
                    return contentBytes;

                case DictionaryAttribute.TYPE_INTEGER:
                case DictionaryAttribute.TYPE_TAGGED_INTEGER:
                    return BitConverter.ToUInt32(contentBytes.Reverse().ToArray(), 0);

                case DictionaryAttribute.TYPE_IPADDR:
                    return new IPAddress(contentBytes);

                default:
                    return null;
            }
        }


        /// <summary>
        /// Validates a message authenticator attribute if one exists in the packet
        /// Message-Authenticator = HMAC-MD5 (Type, Identifier, Length, Request Authenticator, Attributes)
        /// The HMAC-MD5 function takes in two arguments:
        /// The payload of the packet, which includes the 16 byte Message-Authenticator field filled with zeros
        /// The shared secret
        /// https://www.ietf.org/rfc/rfc2869.txt
        /// </summary>
        /// <returns></returns>
        private Byte[] CalculateMessageAuthenticator(Byte[] packetBytes, Byte[] sharedSecret, Byte[] requestAuthenticator)
        {
            var temp = new Byte[packetBytes.Count()];
            packetBytes.CopyTo(temp, 0);

            if (requestAuthenticator != null)
            {
                requestAuthenticator.CopyTo(temp, 4);
            }

            using (var md5 = new HMACMD5(sharedSecret))
            {
                return md5.ComputeHash(temp);
            }
        }


        /// <summary>
        /// Creates a response authenticator
        /// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
        /// Actually this means it is the response packet with the request authenticator and secret...
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="requestAuthenticator"></param>
        /// <param name="packetBytes"></param>
        /// <returns>Response authenticator for the packet</returns>
        private Byte[] CalculateResponseAuthenticator(Byte[] sharedSecret, Byte[] requestAuthenticator, Byte[] packetBytes)
        {
            var responseAuthenticator = packetBytes.Concat(sharedSecret).ToArray();
            Buffer.BlockCopy(requestAuthenticator, 0, responseAuthenticator, 4, 16);

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(responseAuthenticator);
            }
        }


        /// <summary>
        /// Calculate the request authenticator used in accounting, disconnect and coa requests
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="packetBytes"></param>
        /// <returns></returns>
        internal Byte[] CalculateRequestAuthenticator(Byte[] sharedSecret, Byte[] packetBytes)
        {
            return CalculateResponseAuthenticator(sharedSecret, new Byte[16], packetBytes);
        }


        /// <summary>
        /// Get the raw packet bytes
        /// </summary>
        /// <returns></returns>
        public Byte[] GetBytes(IRadiusPacket packet)
        {
            var packetBytes = new List<Byte>
            {
                (Byte)packet.Code,
                packet.Identifier
            };
            packetBytes.AddRange(new Byte[18]); // Placeholder for length and authenticator

            var messageAuthenticatorPosition = 0;
            foreach (var attribute in packet.Attributes)
            {
                // todo add logic to check attribute object type matches type in dictionary?
                foreach (var value in attribute.Value)
                {
                    var contentBytes = GetAttributeValueBytes(value);
                    var headerBytes = new Byte[2];

                    var attributeType = _radiusDictionary.GetAttribute(attribute.Key);
                    switch (attributeType)
                    {
                        case DictionaryVendorAttribute _attributeType:
                            headerBytes = new Byte[8];
                            headerBytes[0] = 26; // VSA type

                            var vendorId = BitConverter.GetBytes(_attributeType.VendorId);
                            Array.Reverse(vendorId);
                            Buffer.BlockCopy(vendorId, 0, headerBytes, 2, 4);
                            headerBytes[6] = (Byte)_attributeType.VendorCode;
                            headerBytes[7] = (Byte)(2 + contentBytes.Length);  // length of the vsa part
                            break;

                        case DictionaryAttribute _attributeType:
                            headerBytes[0] = attributeType.Code;

                            // Encrypt password if this is a User-Password attribute
                            if (_attributeType.Code == 2)
                            {
                                contentBytes = RadiusPassword.Encrypt(packet.SharedSecret, packet.Authenticator, contentBytes);
                            }
                            else if (_attributeType.Code == 80)    // Remember the position of the message authenticator, because it has to be added after everything else
                            {
                                messageAuthenticatorPosition = packetBytes.Count;
                            }
                            break;

                        default:
                            throw new InvalidOperationException("Unknown attribute {attribute.Key}, check spelling or dictionary");
                    }

                    headerBytes[1] = (Byte)(headerBytes.Length + contentBytes.Length);
                    packetBytes.AddRange(headerBytes);
                    packetBytes.AddRange(contentBytes);
                }
            }

            // Note the order of the bytes...
            var packetLengthBytes = BitConverter.GetBytes(packetBytes.Count);
            packetBytes[2] = packetLengthBytes[1];
            packetBytes[3] = packetLengthBytes[0];

            var packetBytesArray = packetBytes.ToArray();

            if (packet.Code == PacketCode.AccountingRequest || packet.Code == PacketCode.DisconnectRequest || packet.Code == PacketCode.CoaRequest)
            {
                if (messageAuthenticatorPosition != 0)
                {
                    var temp = new Byte[16];
                    Buffer.BlockCopy(temp, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
                    var messageAuthenticatorBytes = CalculateMessageAuthenticator(packetBytesArray, packet.SharedSecret, null);
                    Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
                }

                var authenticator = CalculateRequestAuthenticator(packet.SharedSecret, packetBytesArray);
                Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);               
            }
            else if (packet.Code == PacketCode.StatusServer)
            {
                var authenticator = packet.RequestAuthenticator != null ? CalculateResponseAuthenticator(packet.SharedSecret, packet.RequestAuthenticator, packetBytesArray) : packet.Authenticator;
                Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);

                if (messageAuthenticatorPosition != 0)
                {
                    var temp = new Byte[16];
                    Buffer.BlockCopy(temp, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
                    var messageAuthenticatorBytes = CalculateMessageAuthenticator(packetBytesArray, packet.SharedSecret, packet.RequestAuthenticator);
                    Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
                }              
            }
            else
            {
                if (packet.RequestAuthenticator == null)
                {
                    Buffer.BlockCopy(packet.Authenticator, 0, packetBytesArray, 4, 16);
                }

                if (messageAuthenticatorPosition != 0)
                {
                    var temp = new Byte[16];
                    Buffer.BlockCopy(temp, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
                    var messageAuthenticatorBytes = CalculateMessageAuthenticator(packetBytesArray, packet.SharedSecret, packet.RequestAuthenticator);
                    Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
                }

                if (packet.RequestAuthenticator != null)
                {
                    var authenticator = CalculateResponseAuthenticator(packet.SharedSecret, packet.RequestAuthenticator, packetBytesArray);
                    Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);
                }
            }

            return packetBytesArray;
        }


        /// <summary>
        /// Gets the byte representation of an attribute object
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private Byte[] GetAttributeValueBytes(Object value)
        {
            switch (value)
            {
                case String _value:
                    return Encoding.UTF8.GetBytes(_value);

                case UInt32 _value:
                    var contentBytes = BitConverter.GetBytes(_value);
                    Array.Reverse(contentBytes);
                    return contentBytes;

                case Byte[] _value:
                    return _value;

                case IPAddress _value:
                    return _value.GetAddressBytes();

                default:
                    throw new NotImplementedException();
            }
        }
    }
}
