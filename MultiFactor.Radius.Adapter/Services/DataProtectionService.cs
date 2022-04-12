using MultiFactor.Radius.Adapter.Configuration;
using System;
using System.Security.Cryptography;
using System.Text;

namespace MultiFactor.Radius.Adapter.Services
{
    /// <summary>
    /// Protect sensitive data with Windows DPAPI SDK
    /// </summary>
    public class DataProtectionService
    {
        public string Protect(ClientConfiguration clientConfig, string data)
        {
            if (clientConfig == null) throw new ArgumentNullException(nameof(clientConfig));
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(data);

            var additionalEntropy = StringToBytes(clientConfig.MultiFactorApiSecret);
            return ToBase64(ProtectedData.Protect(StringToBytes(data), additionalEntropy, DataProtectionScope.CurrentUser));
        }

        public string Unprotect(ClientConfiguration clientConfig, string data)
        {
            if (clientConfig == null) throw new ArgumentNullException(nameof(clientConfig));
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(data);

            var additionalEntropy = StringToBytes(clientConfig.MultiFactorApiSecret);
            return BytesToString(ProtectedData.Unprotect(FromBase64(data), additionalEntropy, DataProtectionScope.CurrentUser));
        }

        private byte[] StringToBytes(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        private string BytesToString(byte[] b)
        {
            return Encoding.UTF8.GetString(b);
        }

        private string ToBase64(byte[] data)
        {
            return Convert.ToBase64String(data);
        }

        private byte[] FromBase64(string text)
        {
            return Convert.FromBase64String(text);
        }
    }

}
