using System;
using System.IO;

namespace MultiFactor.Radius.Adapter.Core
{
    public static class Constants
    {
        public static readonly string ApplicationPath = $"{Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory)}{Path.DirectorySeparatorChar}";

        public static class Configuration
        {
            public const string SyslogOutputTemplate = "syslog-output-template";
            public const string FileLogOutputTemplate = "file-log-output-template";
            public const string ConsoleLogOutputTemplate = "console-log-output-template";

            public static class PciDss
            {
                public const string InvalidCredentialDelay = "invalid-credential-delay";
            }

            public const string AuthenticationCacheLifetime = "authentication-cache-lifetime";
            public const string CallingStationIdAttribute = "calling-station-id-attribute";
            public const string PrivacyMode = "privacy-mode";
            public const string PreAuthnMode = "second-pre-authentication-method";

            [Obsolete("Use AuthenticationCacheLifetime instead")]
            public const string BypassSecondFactorPeriod = "bypass-second-factor-period";
        }
    }
}
