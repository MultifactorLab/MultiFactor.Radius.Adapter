using MultiFactor.Radius.Adapter.Configuration;
using Serilog.Core;
using Serilog.Events;
using System;

namespace MultiFactor.Radius.Adapter.Extensions
{
    public static class LoggingLevelSwitchExtensions
    {
        public static void SetLogLevel(this LoggingLevelSwitch loggingLevelSwitch, ServiceConfiguration serviceConfiguration)
        {
            if (serviceConfiguration is null)
            {
                throw new ArgumentNullException(nameof(serviceConfiguration));
            }

            if (!Enum.TryParse<LogEventLevel>(serviceConfiguration.LogLevel, out var logLevel))
            {
                logLevel = LogEventLevel.Information;
            }
            loggingLevelSwitch.MinimumLevel = logLevel;
        }
    }
}
