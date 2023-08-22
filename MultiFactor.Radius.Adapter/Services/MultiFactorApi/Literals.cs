namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi
{
    public static class Literals
    {
        public static class RadiusCode
        {
            public const string Granted = "Granted";
            public const string Denied = "Denied";
            public const string AwaitingAuthentication = "AwaitingAuthentication";
        }

        public static class Configuration
        {
            public const string PrivacyMode = "privacy-mode";
            public const string PreAuthnMode = "second-pre-authentication-method";
        }
    }
}
