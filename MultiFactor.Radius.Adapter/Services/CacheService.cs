//Copyright(c) 2021 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
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

        public void RegisterPasswordChangeRequest(PasswordChangeRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            _cache.Set(request.Id, request, DateTimeOffset.UtcNow.AddMinutes(5));
        }

        public void Remove(string id)
        {
            if (!string.IsNullOrEmpty(id))
            {
                _cache.Remove(id);
            }
        }

        public PasswordChangeRequest GetPasswordChangeRequest(string id)
        {
            if (id == null) return null;
            return _cache.Get(id) as PasswordChangeRequest;
        }
    }
}
