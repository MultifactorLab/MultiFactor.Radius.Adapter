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
using System.Security.Cryptography;
using System.Text;

namespace MultiFactor.Radius.Adapter.Core
{
    public static class RadiusPassword
    {
        /// <summary>
        /// Encrypt/decrypt using XOR
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private static byte[] EncryptDecrypt(byte[] input, byte[] key)
        {
            var output = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                output[i] = (byte)(input[i] ^ key[i]);
            }
            return output;
        }


        /// <summary>
        /// Create a radius shared secret key
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="Stuff"></param>
        /// <returns></returns>
        private static byte[] CreateKey(byte[] sharedSecret, byte[] authenticator)
        {
            var key = new byte[16 + sharedSecret.Length];
            Buffer.BlockCopy(sharedSecret, 0, key, 0, sharedSecret.Length);
            Buffer.BlockCopy(authenticator, 0, key, sharedSecret.Length, authenticator.Length);

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(key);
            }
        }

        /// <summary>
        /// Decrypt user password
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="authenticator"></param>
        /// <param name="passwordBytes"></param>
        /// <returns></returns>
        public static string Decrypt(RadiusPacketId packetId, byte[] passwordBytes)
        {
            return Decrypt(packetId, passwordBytes, Encoding.UTF8);
        }

        /// <summary>
        /// Decrypt user password
        /// </summary>
        public static string Decrypt(RadiusPacketId packetId, byte[] passwordBytes, Encoding encoding)
        {
            var key = CreateKey(packetId.SharedSecret.Bytes, packetId.Authenticator);
            var bytes = new byte[passwordBytes.Length];

            var temp = new byte[16];
            for (var n = 1; n <= passwordBytes.Length / 16; n++)
            {
                Buffer.BlockCopy(passwordBytes, (n - 1) * 16, temp, 0, 16);

                var block = EncryptDecrypt(temp, key);
                Buffer.BlockCopy(block, 0, bytes, (n - 1) * 16, 16);

                key = CreateKey(packetId.SharedSecret.Bytes, temp);
            }

            var ret = encoding.GetString(bytes);
            return ret.Replace("\0", "");
        }

        /// <summary>
        /// Encrypt a password
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="authenticator"></param>
        /// <param name="passwordBytes"></param>
        /// <returns></returns>
        public static byte[] Encrypt(RadiusPacketId packetId, byte[] passwordBytes)
        {
            Array.Resize(ref passwordBytes, passwordBytes.Length + (16 - (passwordBytes.Length % 16)));

            var key = CreateKey(packetId.SharedSecret.Bytes, packetId.Authenticator);
            var bytes = new byte[passwordBytes.Length];
            var temp = new byte[16];
            for (var n = 1; n <= passwordBytes.Length / 16; n++)
            {
                Buffer.BlockCopy(passwordBytes, (n - 1) * 16, temp, 0, 16);
                var xor = EncryptDecrypt(temp, key);
                Buffer.BlockCopy(xor, 0, bytes, (n - 1) * 16, 16);

                key = CreateKey(packetId.SharedSecret.Bytes, xor);
            }

            return bytes;
        }
    }
}
