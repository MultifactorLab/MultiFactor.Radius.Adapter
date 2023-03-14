using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing;
using MultiFactor.Radius.Adapter.Services;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using MultiFactor.Radius.Adapter.Services.MultiFactorApi;
using Serilog;
using Serilog.Core;
using System.IO;

namespace MultiFactor.Radius.Adapter.Extensions
{
    public static class ServicesConfiguration
    {
        public  static void ConfigureApplicationServices(this IServiceCollection services, LoggingLevelSwitch levelSwitch, string syslogInfoMessage)
        {
            services.AddSingleton(Log.Logger);
            services.AddSingleton<IRadiusDictionary>(prov =>
            {
                var dictionaryPath = $"{Core.Constants.ApplicationPath}Content{Path.DirectorySeparatorChar}radius.dictionary";
                return new RadiusDictionary(dictionaryPath, prov.GetRequiredService<ILogger>());
            });
            services.AddSingleton(prov =>
            {
                var config = ServiceConfiguration.Load(prov.GetRequiredService<IRadiusDictionary>(), prov.GetRequiredService<ILogger>());

                levelSwitch.SetLogLevel(config);
                Log.Logger.Information($"Logging level: {levelSwitch.MinimumLevel}");
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

            services.AddSingleton(prov => new RandomWaiter(prov.GetRequiredService<ServiceConfiguration>().InvalidCredentialDelay));
            services.AddSingleton<AuthenticatedClientCache>();
        }
    }
}
