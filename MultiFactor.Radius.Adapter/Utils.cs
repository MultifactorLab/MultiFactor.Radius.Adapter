using System;

namespace MultiFactor.Radius.Adapter.Core
{
    public static class Utils
    {
        /// <summary>
        /// Convert a string of hex encoded bytes to a byte array
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static Byte[] StringToByteArray(String hex)
        {
            var NumberChars = hex.Length;
            var bytes = new Byte[NumberChars / 2];
            for (var i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }


        /// <summary>
        /// Convert a byte array to a string of hex encoded bytes
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static String ToHexString(this Byte[] bytes)
        {
            return bytes != null ? BitConverter.ToString(bytes).ToLowerInvariant().Replace("-", "") : null;    
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
    }
}
