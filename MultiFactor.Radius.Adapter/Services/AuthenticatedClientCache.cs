using MultiFactor.Radius.Adapter.Configuration;
using Serilog;
using System;
using System.Collections.Concurrent;

namespace MultiFactor.Radius.Adapter.Services
{
    public class AuthenticatedClientCache
    {
        private static readonly ConcurrentDictionary<string, AuthenticatedClient> _authenticatedClients = new ConcurrentDictionary<string, AuthenticatedClient>();
        private readonly ILogger _logger;

        public AuthenticatedClientCache(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public bool TryHitCache(string callingStationId, string userName, ClientConfiguration clientConfiguration)
        {
            if (!clientConfiguration.AuthenticationCacheLifetime.Enabled) return false;

            if (string.IsNullOrEmpty(callingStationId))
            {
                _logger.Warning($"Remote host parameter miss for user {userName}");
                return false;
            }

            var id = AuthenticatedClient.ParseId(clientConfiguration.Name, callingStationId, userName);
            if (!_authenticatedClients.TryGetValue(id, out var authenticatedClient))
            {
                return false;
            }

            _logger.Debug($"User {userName} with calling-station-id {callingStationId} authenticated {authenticatedClient.Elapsed.ToString("hh\\:mm\\:ss")} ago. Authentication session period: {clientConfiguration.AuthenticationCacheLifetime.Lifetime}");

            if (authenticatedClient.Elapsed <= clientConfiguration.AuthenticationCacheLifetime.Lifetime)
            {
                return true;
            }

            _authenticatedClients.TryRemove(id, out _);

            return false;
        }

        public void SetCache(string callingStationId, string userName, ClientConfiguration clientConfiguration)
        {
            if (!clientConfiguration.AuthenticationCacheLifetime.Enabled || string.IsNullOrEmpty(callingStationId)) return;

            var client = AuthenticatedClient.Create(clientConfiguration.Name, callingStationId, userName);
            if (!_authenticatedClients.ContainsKey(client.Id))
            {
                _authenticatedClients.TryAdd(client.Id, client);
            }
        }
    }
}
