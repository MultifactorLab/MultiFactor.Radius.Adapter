using MultiFactor.Radius.Adapter.Configuration;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

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

        public bool TryHitCache(string callingStationId, string userName, ClientConfiguration clientConfiguration, IReadOnlyCollection<string> userGroups)
        {
            if (userGroups is null)
                throw new ArgumentException(nameof(userGroups));
            
            if (!clientConfiguration.AuthenticationCacheLifetime.Enabled) return false;
            
            var cacheGroups = clientConfiguration.AuthenticationCacheLifetime.AuthenticationCacheGroups;
            var lowercaseUserGroups = userGroups.Select(x => x.ToLower().Trim());
            var groupsStr = string.Join(", ", cacheGroups);
            if (cacheGroups.Count > 0 && !cacheGroups.Intersect(lowercaseUserGroups).Any())
            {
                _logger.Debug("Skip auth caching. User '{userName}' is not a member of any authentication cache groups: ({groups})", userName, groupsStr);
                return false;
            }

            if (!string.IsNullOrEmpty(groupsStr))
            {
                _logger.Debug("User '{userName}' is a member of authentication cache groups: ({groups})", userName, groupsStr);
            }

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
