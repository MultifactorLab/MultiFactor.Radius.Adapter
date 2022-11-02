using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Syslog;
using Serilog;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Compact;
using Serilog.Sinks.Syslog;
using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace MultiFactor.Radius.Adapter.Extensions
{
    public static class LoggingConfiguration
    {
        public static LoggerConfiguration ConfigureConsoleLogging(this LoggerConfiguration loggerConfiguration)
        {
            var formatter = GetLogFormatter();
            if (formatter != null)
            {
                loggerConfiguration.WriteTo.Console(formatter, LogEventLevel.Debug);
                return loggerConfiguration;
            }
                       
            var consoleTemplate = GetStringSettingOrNull(Core.Constants.Configuration.ConsoleLogOutputTemplate);
            if (consoleTemplate != null)
            {
                loggerConfiguration.WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Debug, outputTemplate: consoleTemplate);
                return loggerConfiguration;
            }
            
            loggerConfiguration.WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Debug);
            return loggerConfiguration;
        }

        public static LoggerConfiguration ConfigureFileLogging(this LoggerConfiguration loggerConfiguration)
        {
            var defaultFileSize = 1L * 1024 * 1024 * 1024;
            if (!long.TryParse(ConfigurationManager.AppSettings["log-file-max-size-bytes"], out long fileSizeLimitBytes))
            {
                // 1 Gb
                fileSizeLimitBytes = defaultFileSize;
            }
            if (fileSizeLimitBytes == 0)
            {
                fileSizeLimitBytes = defaultFileSize;
            }

            var path = Core.Constants.ApplicationPath;
            var formatter = GetLogFormatter();
            if (formatter != null)
            {
                loggerConfiguration.WriteTo.File(
                    formatter,
                    $"{path}Logs{Path.DirectorySeparatorChar}log-.txt",
                    rollingInterval: RollingInterval.Day,
                    fileSizeLimitBytes: fileSizeLimitBytes);
                return loggerConfiguration;
            }   

            var fileTemplate = GetStringSettingOrNull(Core.Constants.Configuration.FileLogOutputTemplate);
            if (fileTemplate != null)
            {
                loggerConfiguration.WriteTo.File($"{path}Logs{Path.DirectorySeparatorChar}log-.txt",
                    outputTemplate: fileTemplate,
                    rollingInterval: RollingInterval.Day,
                    fileSizeLimitBytes: fileSizeLimitBytes);
                return loggerConfiguration;
            }
                  
            loggerConfiguration.WriteTo.File($"{path}Logs{Path.DirectorySeparatorChar}log-.txt",
                rollingInterval: RollingInterval.Day,
                fileSizeLimitBytes: fileSizeLimitBytes);
            return loggerConfiguration;
        }

        public static LoggerConfiguration ConfigureSyslogLogging(this LoggerConfiguration loggerConfiguration, out string logMessage)
        {
            logMessage = null;

            var appSettings = ConfigurationManager.AppSettings;
            var sysLogServer = appSettings["syslog-server"];
            if (sysLogServer == null) return loggerConfiguration;

            var uri = new Uri(sysLogServer);
            if (uri.Port == -1)
            {
                throw new ConfigurationErrorsException($"Invalid port number for syslog-server {sysLogServer}");
            }

            var sysLogFormatSetting = appSettings["syslog-format"];
            var sysLogFramerSetting = appSettings["syslog-framer"];
            var sysLogFacilitySetting = appSettings["syslog-facility"];
            var sysLogAppName = appSettings["syslog-app-name"] ?? "multifactor-radius";

            var isJson = ServiceConfiguration.GetLogFormat() == "json";

            var facility = ParseSettingOrDefault(sysLogFacilitySetting, Facility.Auth);
            var format = ParseSettingOrDefault(sysLogFormatSetting, SyslogFormat.RFC5424);
            var framer = ParseSettingOrDefault(sysLogFramerSetting, FramingType.OCTET_COUNTING);

            var template = GetStringSettingOrNull(Core.Constants.Configuration.SyslogOutputTemplate);

            switch (uri.Scheme)
            {
                case "udp":
                    var serverIp = ResolveIP(uri.Host);
                    loggerConfiguration
                        .WriteTo
                        .JsonUdpSyslog(
                            serverIp,
                            port: uri.Port,
                            appName: sysLogAppName,
                            format: format,
                            facility: facility,
                            json: isJson,
                            outputTemplate: template);
                    logMessage = $"Using syslog server: {sysLogServer}, format: {format}, facility: {facility}, appName: {sysLogAppName}";
                    break;
                case "tcp":
                    loggerConfiguration
                        .WriteTo
                        .JsonTcpSyslog(
                            uri.Host,
                            uri.Port,
                            appName: sysLogAppName,
                            format: format,
                            framingType: framer,
                            facility: facility,
                            json: isJson,
                            outputTemplate: template);
                    logMessage = $"Using syslog server {sysLogServer}, format: {format}, framing: {framer}, facility: {facility}, appName: {sysLogAppName}";
                    break;
                default:
                    throw new NotImplementedException($"Unknown scheme {uri.Scheme} for syslog-server {sysLogServer}. Expected udp or tcp");
            }

            return loggerConfiguration;
        }

        private static ITextFormatter GetLogFormatter()
        {
            var format = ServiceConfiguration.GetLogFormat();
            switch (format?.ToLower())
            {
                case "json":
                    return new RenderedCompactJsonFormatter();
                default:
                    return null;
            }
        }

        private static string GetStringSettingOrNull(string key)
        {
            var value = ConfigurationManager.AppSettings[key];
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        private static TEnum ParseSettingOrDefault<TEnum>(string setting, TEnum defaultValue) where TEnum : struct
        {
            if (Enum.TryParse<TEnum>(setting, out var val))
            {
                return val;
            }

            return defaultValue;
        }

        private static string ResolveIP(string host)
        {
            if (!IPAddress.TryParse(host, out var addr))
            {
                addr = Dns.GetHostAddresses(host)
                    .First(x => x.AddressFamily == AddressFamily.InterNetwork); //only ipv4

                return addr.ToString();
            }

            return host;
        }
    }
}
