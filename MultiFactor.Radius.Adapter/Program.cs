using MultiFactor.Radius.Adapter.Core;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using System;
using System.IO;
using System.Reflection;
using System.ServiceProcess;

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
                .WriteTo.Console(LogEventLevel.Debug)
                .WriteTo.File($"{path}Logs{Path.DirectorySeparatorChar}log-.txt", rollingInterval: RollingInterval.Day);

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
                //init configuration
                var configuration = Configuration.Load();

                SetLogLevel(configuration.LogLevel, levelSwitch);

                var dictionaryPath = path + "Content" + Path.DirectorySeparatorChar + "radius.dictionary";
                var dictionary = new RadiusDictionary(dictionaryPath, Log.Logger);

                var adapterService = new AdapterService(configuration, dictionary, Log.Logger);

                if (Environment.UserInteractive)
                {
                    //start as console
                    Log.Logger.Information("Console mode");
                    Log.Logger.Information("Press CTRL+C to exit");

                    Console.CancelKeyPress += delegate { adapterService.StopServer(); };
                    
                    adapterService.StartServer();

                    Console.ReadLine();
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
            catch(Exception ex)
            {
                Log.Logger.Error(ex, "Unable to start");
            }
        }

        private static void InstallService()
        {
            Log.Logger.Information("Installing service MFRadiusAdapter");
            System.Configuration.Install.ManagedInstallerClass.InstallHelper(new string[] { "/i", Assembly.GetExecutingAssembly().Location });
            Log.Logger.Information("Service installed");
            Log.Logger.Information("Use 'net start MFRadiusAdapter' to run");
            Log.Logger.Information("Press any key to exit");
            Console.ReadKey();
        }

        public static void UnInstallService()
        {
            Log.Logger.Information("UnInstalling service MFRadiusAdapter");
            System.Configuration.Install.ManagedInstallerClass.InstallHelper(new string[] { "/u", Assembly.GetExecutingAssembly().Location });
            Log.Logger.Information("Service uninstalled");
            Log.Logger.Information("Press any key to exit");
            Console.ReadKey();
        }

        private static void SetLogLevel(string level, LoggingLevelSwitch levelSwitch)
        {
            switch (level)
            {
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
    }
}
