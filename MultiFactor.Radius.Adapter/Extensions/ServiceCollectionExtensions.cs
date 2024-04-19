using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Core.Http;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing;
using MultiFactor.Radius.Adapter.Services;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using MultiFactor.Radius.Adapter.Services.MultiFactorApi;
using Serilog;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;

namespace MultiFactor.Radius.Adapter.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection ConfigureApplicationServices(this IServiceCollection services, LoggingLevelSwitch levelSwitch, Dictionary<KnownLineArg, string> arguments, string syslogInfoMessage)
        {
            services.AddSingleton(Log.Logger);
            services.AddSingleton(new PassedLineArguments(arguments));
            services.AddSingleton<IApplicationPath, DefaultApplicationPath>();
            services.AddSingleton<IRadiusDictionary>(prov =>
            {
                var appPath = prov.GetRequiredService<IApplicationPath>().GetApplicationPath();
                var dictionaryPath = $"{appPath}Content{Path.DirectorySeparatorChar}radius.dictionary";
                return new RadiusDictionary(dictionaryPath, prov.GetRequiredService<ILogger>());
            });
            services.AddSingleton<IRootConfigurationProvider, DefaultRootConfigurationProvider>();
            services.AddSingleton<IClientConfigurationsProvider, DefaultClientConfigurationsProvider>();
            services.AddSingleton(prov =>
            {
                var rootConfigProv = prov.GetRequiredService<IRootConfigurationProvider>();
                var rootConfig = rootConfigProv.GetRootConfiguration();
                var dict = prov.GetRequiredService<IRadiusDictionary>();
                var logger = prov.GetRequiredService<ILogger>();
                var serviceConfig = ServiceConfiguration.Load(rootConfig, dict, logger);

                levelSwitch.SetLogLevel(serviceConfig);
                Log.Logger.Information($"Logging level: {levelSwitch.MinimumLevel}");
                if (syslogInfoMessage != null)
                {
                    Log.Logger.Information(syslogInfoMessage);
                }

                return serviceConfig;
            });
            services.AddScoped<IRadiusPacketParser, RadiusPacketParser>();
            services.AddSingleton<IRadiusResponseSender, RealRadiusResponseSender>();
            services.AddSingleton<RadiusServer>();
            services.AddSingleton<CacheService>();
            services.AddSingleton<RadiusRouter>();
            services.AddSingleton<AdapterService>();
            services.AddSingleton<ActiveDirectoryServicesProvider>();
            services.AddSingleton(prov => prov.GetRequiredService<ActiveDirectoryServicesProvider>().GetServices());
            services.AddHttpContextAccessor();

            services.AddSingleton<MultifactorApiClient>();
            services.AddSingleton<MultifactorApiAdapter>();

            services.AddHttpClientWithProxy();
            services.AddSingleton<PasswordChangeHandler>();
            services.AddSingleton<ActiveDirectoryMembershipVerifier>();
            services.AddSingleton<ForestMetadataCache>();
            services.AddSingleton<NetbiosService>();

            services.AddSingleton<IFirstAuthFactorProcessor, ActiveDirectoryFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, AdLdsFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, RadiusFirstAuthFactorProcessor>();
            services.AddSingleton<IFirstAuthFactorProcessor, AnonymousProcessor>();
            services.AddSingleton<FirstAuthFactorProcessorProvider>();

            services.AddSingleton<AuthenticatedClientCache>();

            services.AddSingleton<AdLdsService>();
            services.AddSingleton<LdapConnectionFactory>();
            services.AddTransient<Func<IPEndPoint, IUdpClient>>(prov => endpoint => new RealUdpClient(endpoint));

            return services;
        }

        /// <summary>
        /// Добавляет HttpClient с прокси, если это задано в настройках.
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        public static void AddHttpClientWithProxy(this IServiceCollection services)
        {
            services.AddTransient<MfTraceIdHeaderSetter>();
            services.AddHttpClient(nameof(MultifactorApiClient), (prov, client) =>
            {
                var conf = prov.GetService<ServiceConfiguration>();
                client.Timeout = conf.ApiTimeout;
            })
            .ConfigurePrimaryHttpMessageHandler(prov =>
            {
                var conf = prov.GetService<ServiceConfiguration>();
                var handler = new HttpClientHandler();
                if (string.IsNullOrWhiteSpace(conf.ApiProxy))
                {
                    return handler;
                }

                var logger = prov.GetRequiredService<ILogger>();
                logger.Debug($"Using proxy {conf.ApiProxy}");

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
