//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;
using System.Text;

namespace MultiFactor.Radius.Adapter.Core
{
    public static class Utils
    {
        /// <summary>
        /// Convert a string of hex encoded bytes to a byte array
        /// </summary>
        public static byte[] StringToByteArray(string hex)
        {
            var NumberChars = hex.Length;
            var bytes = new byte[NumberChars / 2];
            for (var i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// Convert a byte array to a string of hex encoded bytes
        /// </summary>
        public static string ToHexString(this byte[] bytes)
        {
            return bytes != null ? BitConverter.ToString(bytes).ToLowerInvariant().Replace("-", "") : null;    
        }

        /// <summary>
        /// Base64 encoded string
        /// </summary>
        public static string Base64(this byte[] bytes)
        {
            if (bytes != null)
            {
                return Convert.ToBase64String(bytes);
            }
            return null;
        }

        /// <summary>
        /// Converts string from base64 to utf-8 
        /// </summary>
        /// <param name="st"></param>
        /// <returns></returns>
        public static string Base64toUtf8(this string st)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(st));
        }

        /// <summary>
        /// User name without domain
        /// </summary>
        public static string CanonicalizeUserName(string userName)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException(nameof(userName));
            }

            var identity = userName.ToLower();

            var index = identity.IndexOf("\\");
            if (index > 0)
            {
                identity = identity.Substring(index + 1);
            }

            index = identity.IndexOf("@");
            if (index > 0)
            {
                identity = identity.Substring(0, index);
            }

            return identity;
        }

        /// <summary>
        /// Check if username does not contains domain prefix or suffix
        /// </summary>
        public static bool IsCanicalUserName(string userName)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException(nameof(userName));
            }

            return userName.IndexOfAny(new[] { '\\', '@' }) == -1;
        }
    }
}
