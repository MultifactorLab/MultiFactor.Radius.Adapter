//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Extensions;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using System;
using System.Collections.Generic;
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
            var levelSwitch = new LoggingLevelSwitch(LogEventLevel.Information);
            var loggerConfiguration = new LoggerConfiguration()
                .MinimumLevel.ControlledBy(levelSwitch)
                .Enrich.FromLogContext()
                .ConfigureConsoleLogging()
                .ConfigureFileLogging()
                .ConfigureSyslogLogging(out var syslogInfoMessage);

            Log.Logger = loggerConfiguration.CreateLogger();

            var arguments = new Dictionary<KnownLineArg, string>();

            var install = false;
            var uninstall = false;

            if (args.Length != 0)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i].StartsWith("/"))
                    {
                        switch (args[i])
                        {
                            case "/i":
                                install = true;
                                continue;

                            case "/u":
                                uninstall = false;
                                continue;

                            default:
                                Log.Logger.Warning($"Unknown command line argument on {i} position: {args[0]}");
                                return;
                        }
                    }

                    var username = args[i];
                    arguments.Add(KnownLineArg.ACT_AS_USER, username);
                    if (string.IsNullOrWhiteSpace(username)) 
                    {
                        Log.Logger.Warning($"Invalid command line argument on {i} position: {args[0]}");
                        return;
                    }

                    if (args.Length <= i + 1)
                    {
                        Log.Logger.Warning($"Empty command line argument near '{username}'");
                        return;
                    }
                    
                    var pwd = args[i + 1];
                    arguments.Add(KnownLineArg.ACT_AS_USER_PWD, pwd);
                    if (string.IsNullOrWhiteSpace(pwd)) 
                    {
                        Log.Logger.Warning($"Invalid or empty command line argument '{username}'");
                        return;
                    }

                    i++;

                }

                if (install)
                {
                    InstallService();
                    return;
                }
                
                if (uninstall)
                {
                    UnInstallService();
                    return;
                }
            }

            ServiceProvider provider = null; 
            try
            {
                var services = new ServiceCollection();
                services.ConfigureApplicationServices(levelSwitch, arguments, syslogInfoMessage);
                provider = services.BuildServiceProvider();

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
            finally 
            {
                provider?.Dispose();
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
    }
}