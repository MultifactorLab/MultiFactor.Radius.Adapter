using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Extensions;
using MultiFactor.Radius.Adapter.Server;
using Serilog.Core;
using Serilog.Events;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Tests.Fixtures
{
    internal class TestRadiusAdapterServer
    {
        private readonly IServiceProvider _serviceProvider;

        public IPEndPoint LocalEndpoint { get; }

        private TestRadiusAdapterServer(IServiceProvider serviceProvider, IPEndPoint localEndpoint)
        {
            _serviceProvider = serviceProvider;
            LocalEndpoint = localEndpoint;
        }

        public static TestRadiusAdapterServer Create(string ip, int port, 
            Action<TestConfigProviderOptions> configure = null, 
            Action<IServiceCollection> configureServices = null)
        {
            if (ip is null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            var endpoint = new IPEndPoint(IPAddress.Parse(ip), port);
            var services = new ServiceCollection()
                .ConfigureApplicationServices(new LoggingLevelSwitch(LogEventLevel.Information), new Dictionary<KnownLineArg, string>(), null)

                .AddSingleton(new TestUdpClient(endpoint))
                .ReplaceService<Func<IPEndPoint, IUdpClient>>(prov => e => prov.GetRequiredService<TestUdpClient>())
                .AddSingleton(configure ?? (cfg => { }))

                .AddSingleton<TestRadiusResponseSender>()
                .ReplaceService<IRadiusResponseSender>(prov => prov.GetRequiredService<TestRadiusResponseSender>())

                .ReplaceService<IRootConfigurationProvider, TestRootConfigProvider>()
                .ReplaceService<IClientConfigurationsProvider, TestClientConfigsProvider>()
                .ReplaceService<IApplicationPath, TestAppPath>();

            configureServices?.Invoke(services);

            var provider = services.BuildServiceProvider();
            return new TestRadiusAdapterServer(provider, endpoint);
        }

        public void SendData(byte[] data)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var cli = _serviceProvider.GetRequiredService<TestUdpClient>();
            cli.SetDatagram(data);
        }

        public void Start()
        {
            var srv = _serviceProvider.GetRequiredService<RadiusServer>();
            srv.Start();
        }

        public Task<byte[]> ReceiveDataAsync()
        {
            var cli = _serviceProvider.GetRequiredService<TestUdpClient>();
            return cli.GetSentDataAsync();
        }

        public TService Service<TService>() where TService : class => _serviceProvider.GetRequiredService<TService>();
    }
}
