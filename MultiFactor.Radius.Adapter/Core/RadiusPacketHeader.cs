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
using System.Net.Sockets;
using System.Security.Cryptography;

namespace MultiFactor.Radius.Adapter.Core
{
    public class RadiusPacketHeader
    {
        public PacketCode Code { get; }
        public byte Identifier { get; }
        public SharedSecret SharedSecret { get; }
        public byte[] Authenticator { get; }

        private RadiusPacketHeader(PacketCode code, byte identifier, byte[] authenticator, SharedSecret sharedSecret)
        {
            Code = code;
            Identifier = identifier;
            Authenticator = authenticator;
            SharedSecret = sharedSecret;
        }

        public static RadiusPacketHeader Parse(byte[] packet, SharedSecret sharedSecret)
        {
            if (packet is null)
            {
                throw new ArgumentNullException(nameof(packet));
            }

            if (sharedSecret is null)
            {
                throw new ArgumentNullException(nameof(sharedSecret));
            }

            var code = (PacketCode)packet[RadiusFieldOffsets.CodeFieldPosition];
            var identifier = packet[RadiusFieldOffsets.IdentifierFieldPosition];

            var authenticator = new byte[RadiusFieldOffsets.AuthenticatorFieldLength];
            Buffer.BlockCopy(packet, RadiusFieldOffsets.AuthenticatorFieldPosition, authenticator, 0, RadiusFieldOffsets.AuthenticatorFieldLength);

            return new RadiusPacketHeader(code, identifier, authenticator, sharedSecret);
        }

        public static RadiusPacketHeader Create(PacketCode code, byte identifier, SharedSecret sharedSecret)
        {
            if (sharedSecret is null)
            {
                throw new ArgumentNullException(nameof(sharedSecret));
            }

            var auth = new byte[RadiusFieldOffsets.AuthenticatorFieldLength];
            // Generate random authenticator for access request packets
            if (code == PacketCode.AccessRequest || code == PacketCode.StatusServer)
            {
                using (var csp = RandomNumberGenerator.Create())
                {
                    csp.GetNonZeroBytes(auth);
                }
            }

            return new RadiusPacketHeader(code, identifier, auth, sharedSecret);
        }
    }
}
