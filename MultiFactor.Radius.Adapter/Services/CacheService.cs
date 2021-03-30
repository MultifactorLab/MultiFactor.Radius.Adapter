//Copyright(c) 2021 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using Serilog;
using System;
using System.Net;
using System.Runtime.Caching;

namespace MultiFactor.Radius.Adapter.Services
{
    public class CacheService
    {
        private const int MAX_RECONNECT_ATTEMPTS = 2;

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

        public void RegisterTimeout(IRadiusPacket packet)
        {
            if (IsMicrosoftRDGateway(packet))
            {
                var key = $"rdgw:r:{packet.UserName}:{packet.RemoteHostName}";

                var attemptNumber = (_cache[key] as int? ?? 0) + 1;

                _cache.Set(key, attemptNumber, DateTimeOffset.UtcNow.AddMinutes(2));
            }
        }

        public bool IsContinuousAutoReconnect(IRadiusPacket packet)
        {
            if (IsMicrosoftRDGateway(packet))
            {
                var key = $"rdgw:r:{packet.UserName}:{packet.RemoteHostName}";

                var attemptsCount = _cache[key] as int? ?? 0;

                if (attemptsCount >= MAX_RECONNECT_ATTEMPTS)
                {
                    _cache.Remove(key);
                    return true;
                }
            }

            return false;
        }

        private bool IsMicrosoftRDGateway(IRadiusPacket packet)
        {
            var key = "MS-Network-Access-Server-Type";
            if (packet.Attributes.ContainsKey(key))
            {
                var attr = packet.Attributes["MS-Network-Access-Server-Type"];
                return attr[0] as uint? == 1;
            }
            return false;
        }
    }
}
