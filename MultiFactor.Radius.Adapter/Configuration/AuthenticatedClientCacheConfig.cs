using System;

namespace MultiFactor.Radius.Adapter.Configuration
{
    public class AuthenticatedClientCacheConfig
    {
        public TimeSpan Lifetime { get; }
        public bool Enabled => Lifetime != TimeSpan.Zero;

        public AuthenticatedClientCacheConfig(TimeSpan lifetime)
        {
            Lifetime = lifetime;
        }

        public static AuthenticatedClientCacheConfig CreateFromTimeSpan(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return new AuthenticatedClientCacheConfig(TimeSpan.Zero);
            return new AuthenticatedClientCacheConfig(TimeSpan.ParseExact(value, @"hh\:mm\:ss", null, System.Globalization.TimeSpanStyles.None));
        }
        
        public static AuthenticatedClientCacheConfig CreateFromMinutes(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return new AuthenticatedClientCacheConfig(TimeSpan.Zero);
            return new AuthenticatedClientCacheConfig(TimeSpan.FromMinutes(int.Parse(value)));
        }
    }
}
