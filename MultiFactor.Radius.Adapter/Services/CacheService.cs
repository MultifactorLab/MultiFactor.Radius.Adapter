using MultiFactor.Radius.Adapter.Core;
using Serilog;
using System;
using System.Net;
using System.Runtime.Caching;

namespace MultiFactor.Radius.Adapter.Services
{
    public class CacheService
    {
        private ObjectCache _cache = MemoryCache.Default;
        private readonly ILogger _logger;

        public CacheService(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Check is packet was retransmissed (duplicated)
        /// </summary>
        public bool IsRetransmission(IRadiusPacket requestPacket, IPEndPoint remoteEndpoint)
        {
            //unique key is combination of packet code, client endpoint, user name and request authenticator 
            
            var uniqueKey = requestPacket.CreateUniqueKey(remoteEndpoint);

            if (_cache.Contains(uniqueKey))
            {
                return true;
            }

            _cache.Add(uniqueKey, "1", DateTimeOffset.UtcNow.AddMinutes(1));

            return false;
        }
    }
}
