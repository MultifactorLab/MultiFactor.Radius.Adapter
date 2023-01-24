//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Core.ApplicationOptions;
using MultiFactor.Radius.Adapter.Extensions;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using System;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace MultiFactor.Radius.Adapter
{
    static class Program
    {
        private const string _usrArg = "--usr";
        private const string _pwdArg = "--pwd";

        /// <summary>
        /// Main entry point
        /// </summary>
        static void Main(string[] args)
        {
            var levelSwitch = new LoggingLevelSwitch(LogEventLevel.Information);
            var loggerConfiguration = new LoggerConfiguration()
                .MinimumLevel.ControlledBy(levelSwitch)
                .Enrich.FromLogContext()
                .ConfigureConsoleLogging()
                .ConfigureFileLogging()
                .ConfigureSyslogLogging(out var syslogInfoMessage);

            Log.Logger = loggerConfiguration.CreateLogger();
            var optionsBuilder = ApplicationRunOptions.CreateBuilder();

            try
            {
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
                            for (var i = 0; i < args.Length; i++)
                            {
                                switch (args[i])
                                {
                                    case _usrArg:
                                        optionsBuilder.AddOption(RunOptionName.Usr, GetArgument(args, i++, _usrArg));
                                        continue;

                                    case _pwdArg:
                                        optionsBuilder.AddOption(RunOptionName.Pwd, GetArgument(args, i++, _pwdArg));
                                        continue;

                                    default:
                                        throw new ArgumentException($"Unknown command line argument: {args[i]}");
                                }
                            }
                            break;
                    }
                }
            }
            catch (ArgumentException ex)
            {
                Log.Logger.Warning(ex.Message);
                return;
            }

            GlobalState.SetRunOptions(optionsBuilder.Build());

            try
            {
                var services = new ServiceCollection();
                services.ConfigureApplicationServices(levelSwitch, syslogInfoMessage);
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
                    // start as service
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

        private static void InstallService()
        {
            Log.Logger.Information($"Installing service {ServiceConfiguration.ServiceUnitName}");
            System.Configuration.Install.ManagedInstallerClass.InstallHelper(new string[] { "/i", Assembly.GetExecutingAssembly().Location });
            Log.Logger.Information("Service installed");
            Log.Logger.Information($"Use 'net start {ServiceConfiguration.ServiceUnitName}' to run");
            Log.Logger.Information("Press any key to exit");
            Console.ReadKey();
        }

        private static void UnInstallService()
        {
            Log.Logger.Information($"UnInstalling service {ServiceConfiguration.ServiceUnitName}");
            System.Configuration.Install.ManagedInstallerClass.InstallHelper(new string[] { "/u", Assembly.GetExecutingAssembly().Location });
            Log.Logger.Information("Service uninstalled");
            Log.Logger.Information("Press any key to exit");
            Console.ReadKey();
        }

        private static string GetArgument(string[] args, int position, string argName)
        {
            if (args.Length < position + 2 || string.IsNullOrEmpty(args[position + 1])) throw new ArgumentException($"Empty argument value near the {argName}");

            var val = args[position + 1];
            if (val.StartsWith("--") || val.StartsWith("/")) throw new ArgumentException($"Invalid argument value near the {argName}");

            return val;
        }
    }
}