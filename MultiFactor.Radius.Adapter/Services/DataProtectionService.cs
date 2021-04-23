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
        private Configuration _configuration;

        public DataProtectionService(Configuration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        private byte[] AdditionalEntropy => StringToBytes(_configuration.MultiFactorSharedSecret);

        public string Protect(string data)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(data);

            return ToBase64(ProtectedData.Protect(StringToBytes(data), AdditionalEntropy, DataProtectionScope.CurrentUser));
        }

        public string Unprotect(string data)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(data);
            return BytesToString(ProtectedData.Unprotect(FromBase64(data), AdditionalEntropy, DataProtectionScope.CurrentUser));
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
