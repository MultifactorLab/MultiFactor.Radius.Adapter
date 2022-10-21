//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing;
using MultiFactor.Radius.Adapter.Services;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using MultiFactor.Radius.Adapter.Syslog;
using Serilog;
using Serilog.Core;
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
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace MultiFactor.Radius.Adapter
{
    static class Program
    {
        /// <summary>
        /// Main entry point
        /// </summary>
        static void Main(string[] args)
        {
            var path = Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) + Path.DirectorySeparatorChar;

            //create logging
            var levelSwitch = new LoggingLevelSwitch(LogEventLevel.Information);
            var loggerConfiguration = new LoggerConfiguration()
                .MinimumLevel.ControlledBy(levelSwitch)
                .Enrich.FromLogContext();

            ConfigureStandartLog(path, loggerConfiguration);
            ConfigureSyslog(loggerConfiguration, out var syslogInfoMessage);

            Log.Logger = loggerConfiguration.CreateLogger();

            if (args.Length > 0)
            {
                switch (args[0])
                {
                    case "/i":
                        InstallService();
                        return;
                    case "/u":
                        UnInstallService();
                        return;
                    default:
                        Log.Logger.Warning($"Unknown command line argument: {args[0]}");
                        return;
                }
            }

            try
            {
                var services = new ServiceCollection();
                ConfigureServices(path, levelSwitch, syslogInfoMessage, services);

                var provider = services.BuildServiceProvider();
                var adapterService = provider.GetRequiredService<AdapterService>();

                if (Environment.UserInteractive)
                {
                    //start as console
                    Log.Logger.Information("Console mode");
                    Log.Logger.Information("Press CTRL+C to exit");

                    Console.OutputEncoding = Encoding.UTF8;

                    Serilog.Debugging.SelfLog.Enable(Console.Error);

                    var cts = new CancellationTokenSource();

                    Console.CancelKeyPress += (sender, eventArgs) =>
                    {
                        adapterService.StopServer();
                        eventArgs.Cancel = true;
                        cts.Cancel();
                    };

                    adapterService.StartServer();

                    cts.Token.WaitHandle.WaitOne();
                }
                else
                {
                    //start as service
                    Log.Logger.Information("Service mode");
                    ServiceBase[] ServicesToRun;
                    ServicesToRun = new ServiceBase[]
                    {
                        adapterService
                    };
                    ServiceBase.Run(ServicesToRun);
                }
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"Unable to start: {ex.Message}");
            }
        }

        private static void ConfigureStandartLog(string path, LoggerConfiguration loggerConfiguration)
        {
            var formatter = GetLogFormatter();
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
            if (formatter != null)
            {
                loggerConfiguration
                    .WriteTo.Console(
                        formatter,
                        LogEventLevel.Debug)
                    .WriteTo.File(
                        formatter,
                        $"{path}Logs{Path.DirectorySeparatorChar}log-.txt",
                        rollingInterval: RollingInterval.Day,
                        fileSizeLimitBytes: fileSizeLimitBytes);
            }
            else
            {
                var consoleTemplate = GetStringSettingOrNull(Core.Constants.Configuration.ConsoleLogOutputTemplate);
                if (consoleTemplate != null)
                {
                    loggerConfiguration.WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Debug, outputTemplate: consoleTemplate);
                }
                else
                {
                    loggerConfiguration.WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Debug);
                }

                var fileTemplate = GetStringSettingOrNull(Core.Constants.Configuration.FileLogOutputTemplate);
                if (fileTemplate != null)
                {
                    loggerConfiguration.WriteTo.File($"{path}Logs{Path.DirectorySeparatorChar}log-.txt",
                        outputTemplate: fileTemplate,
                        rollingInterval: RollingInterval.Day,
                        fileSizeLimitBytes: fileSizeLimitBytes);
                }
                else
                {
                    loggerConfiguration.WriteTo.File($"{path}Logs{Path.DirectorySeparatorChar}log-.txt",
                        rollingInterval: RollingInterval.Day,
                        fileSizeLimitBytes: fileSizeLimitBytes);
                }
            }
        }

        private static void InstallService()
        {
            Log.Logger.Information($"Installing service {ServiceConfiguration.ServiceUnitName}");
            System.Configuration.Install.ManagedInstallerClass.InstallHelper(new string[] { "/i", Assembly.GetExecutingAssembly().Location });
            Log.Logger.Information("Service installed");
            Log.Logger.Information($"Use 'net start {ServiceConfiguration.ServiceUnitName}' to run");
            Log.Logger.Information("Press any key to exit");
            Console.ReadKey();
        }

        public static void UnInstallService()
        {
            Log.Logger.Information($"UnInstalling service {ServiceConfiguration.ServiceUnitName}");
            System.Configuration.Install.ManagedInstallerClass.InstallHelper(new string[] { "/u", Assembly.GetExecutingAssembly().Location });
            Log.Logger.Information("Service uninstalled");
            Log.Logger.Information("Press any key to exit");
            Console.ReadKey();
        }

        private static void SetLogLevel(string level, LoggingLevelSwitch levelSwitch)
        {
            switch (level)
            {
                case "Verbose":
                    levelSwitch.MinimumLevel = LogEventLevel.Verbose;
                    break;
                case "Debug":
                    levelSwitch.MinimumLevel = LogEventLevel.Debug;
                    break;
                case "Info":
                    levelSwitch.MinimumLevel = LogEventLevel.Information;
                    break;
                case "Warn":
                    levelSwitch.MinimumLevel = LogEventLevel.Warning;
                    break;
                case "Error":
                    levelSwitch.MinimumLevel = LogEventLevel.Error;
                    break;
            }

            Log.Logger.Information($"Logging level: {levelSwitch.MinimumLevel}");
        }

        private static void ConfigureSyslog(LoggerConfiguration loggerConfiguration, out string logMessage)
        {
            logMessage = null;

            var appSettings = ConfigurationManager.AppSettings;
            var sysLogServer = appSettings["syslog-server"];
            if (sysLogServer == null) return;

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

        private static void ConfigureServices(string path, LoggingLevelSwitch levelSwitch, string syslogInfoMessage, ServiceCollection services)
        {
            services.AddSingleton(Log.Logger);
            services.AddSingleton<IRadiusDictionary>(prov =>
            {
                var dictionaryPath = path + "Content" + Path.DirectorySeparatorChar + "radius.dictionary";
                return new RadiusDictionary(dictionaryPath, prov.GetRequiredService<ILogger>());
            });
            services.AddSingleton(prov =>
            {
                var config = ServiceConfiguration.Load(
                    prov.GetRequiredService<IRadiusDictionary>(),
                    prov.GetRequiredService<ILogger>());

                SetLogLevel(config.LogLevel, levelSwitch);
                if (syslogInfoMessage != null)
                {
                    Log.Logger.Information(syslogInfoMessage);
                }

                return config;
            });
            services.AddScoped<IRadiusPacketParser, RadiusPacketParser>();
            services.AddSingleton<RadiusServer>();
            services.AddSingleton<CacheService>();
            services.AddSingleton<RadiusRouter>();
            services.AddSingleton<AdapterService>();
            services.AddSingleton<ActiveDirectoryServicesProvider>();
            services.AddSingleton(prov => prov.GetRequiredService<ActiveDirectoryServicesProvider>().GetServices());
            services.AddSingleton<MultiFactorApiClient>();
            services.AddSingleton<PasswordChangeHandler>();
            services.AddSingleton<ActiveDirectoryMembershipVerifier>();
            services.AddSingleton<ForestMetadataCache>();

            services.AddSingleton<IFirstAuthFactorProcessor, ActiveDirectoryFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, AdLdsFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, RadiusFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, DefaultFirstAuthFactorProcessor>();
            services.AddSingleton<FirstAuthFactorProcessorProvider>();
        }
    }
}