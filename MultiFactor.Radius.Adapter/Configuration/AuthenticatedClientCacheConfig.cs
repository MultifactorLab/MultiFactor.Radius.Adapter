using System;
using System.Collections.Generic;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Configuration
{
    public class AuthenticatedClientCacheConfig
    {
        public TimeSpan Lifetime { get; }
        public bool Enabled => Lifetime != TimeSpan.Zero;
        public IReadOnlyCollection<string> AuthenticationCacheGroups { get; }

        public AuthenticatedClientCacheConfig(TimeSpan lifetime, IReadOnlyCollection<string> authenticationCacheGroups = null)
        {
            Lifetime = lifetime;
            AuthenticationCacheGroups = authenticationCacheGroups?.Select(x => x.ToLower()).ToArray() ?? Array.Empty<string>();
        }

        public static AuthenticatedClientCacheConfig CreateFromTimeSpan(string value, string authenticationCacheGroups = null)
        {
            if (string.IsNullOrWhiteSpace(value)) return new AuthenticatedClientCacheConfig(TimeSpan.Zero);
            var cacheGroups = SplitCacheGroup(authenticationCacheGroups);
            return new AuthenticatedClientCacheConfig(TimeSpan.ParseExact(value, @"hh\:mm\:ss", null, System.Globalization.TimeSpanStyles.None), cacheGroups);
        }
        
        public static AuthenticatedClientCacheConfig CreateFromMinutes(string value, string authenticationCacheGroups = null)
        {
            if (string.IsNullOrWhiteSpace(value)) return new AuthenticatedClientCacheConfig(TimeSpan.Zero);
            var cacheGroups = SplitCacheGroup(authenticationCacheGroups);
            return new AuthenticatedClientCacheConfig(TimeSpan.FromMinutes(int.Parse(value)), cacheGroups);
        }

        private static string[] SplitCacheGroup(string cacheGroup)
        {
            return cacheGroup
                ?.Split(new[] {';'}, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.ToLower().Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray() ?? Array.Empty<string>();
        }
    }
}
