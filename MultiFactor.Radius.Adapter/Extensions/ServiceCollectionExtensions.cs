using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Core.Http;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing;
using MultiFactor.Radius.Adapter.Services;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using MultiFactor.Radius.Adapter.Services.MultiFactorApi;
using Serilog;
using Serilog.Core;
using System;
using System.IO;
using System.Net.Http;

namespace MultiFactor.Radius.Adapter.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static void ConfigureApplicationServices(this IServiceCollection services, LoggingLevelSwitch levelSwitch, string syslogInfoMessage)
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
            services.AddHttpContextAccessor();
            services.AddSingleton<MultiFactorApiClient>();
            services.AddHttpClientWithProxy();
            services.AddSingleton<PasswordChangeHandler>();
            services.AddSingleton<ActiveDirectoryMembershipVerifier>();
            services.AddSingleton<ForestMetadataCache>();
            services.AddSingleton<NetbiosService>();

            services.AddSingleton<IFirstAuthFactorProcessor, ActiveDirectoryFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, AdLdsFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, RadiusFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, DefaultFirstAuthFactorProcessor>();
            services.AddSingleton<FirstAuthFactorProcessorProvider>();

            services.AddSingleton<AuthenticatedClientCache>();
        }

        /// <summary>
        /// Добавляет HttpClient с прокси, если это задано в настройках.
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        public static void AddHttpClientWithProxy(this IServiceCollection services)
        {
            services.AddTransient<MfTraceIdHeaderSetter>();

            var serviceProvider = services.BuildServiceProvider();
            var logger = serviceProvider.GetRequiredService<ILogger>();
            var conf = serviceProvider.GetService<ServiceConfiguration>();

            services.AddHttpClient(nameof(MultiFactorApiClient), client =>
            {
                client.Timeout = conf.ApiTimeout;
            })
            .ConfigurePrimaryHttpMessageHandler(prov =>
            {
                var handler = new HttpClientHandler();

                if (string.IsNullOrWhiteSpace(conf.ApiProxy)) return handler;
                logger.Debug("Using proxy " + conf.ApiProxy);
                if (!WebProxyFactory.TryCreateWebProxy(conf.ApiProxy, out var webProxy))
                {
                    throw new Exception("Unable to initialize WebProxy. Please, check whether multifactor-api-proxy URI is valid.");
                }
                handler.Proxy = webProxy;

                return handler;
            })
            .AddHttpMessageHandler<MfTraceIdHeaderSetter>();
        }
    }

}
