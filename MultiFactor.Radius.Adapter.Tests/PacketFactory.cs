using System;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Tests
{
    internal static class PacketFactory
    {
        public static byte[] ParseHexString(string hex)
        {           
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();          
        }
    }
}
