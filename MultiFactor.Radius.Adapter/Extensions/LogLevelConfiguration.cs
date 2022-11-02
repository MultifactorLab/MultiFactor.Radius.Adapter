using MultiFactor.Radius.Adapter.Configuration;
using Serilog.Core;
using Serilog.Events;
using System;

namespace MultiFactor.Radius.Adapter.Extensions
{
    public static class LogLevelConfiguration
    {
        public static void SetLogLevel(this LoggingLevelSwitch loggingLevelSwitch, ServiceConfiguration serviceConfiguration)
        {
            if (serviceConfiguration is null)
            {
                throw new ArgumentNullException(nameof(serviceConfiguration));
            }

            switch (serviceConfiguration.LogLevel)
            {
                case "Verbose":
                    loggingLevelSwitch.MinimumLevel = LogEventLevel.Verbose;
                    break;
                case "Debug":
                    loggingLevelSwitch.MinimumLevel = LogEventLevel.Debug;
                    break;
                case "Info":
                    loggingLevelSwitch.MinimumLevel = LogEventLevel.Information;
                    break;
                case "Warn":
                    loggingLevelSwitch.MinimumLevel = LogEventLevel.Warning;
                    break;
                case "Error":
                    loggingLevelSwitch.MinimumLevel = LogEventLevel.Error;
                    break;
            }
        }
    }
}
