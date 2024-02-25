using Microsoft.Extensions.DependencyInjection;
using MultiFactor.Radius.Adapter.Extensions;
using Serilog.Core;

namespace MultiFactor.Radius.Adapter.Tests
{
    public class ConfigurationLoadingTests
    {
        [Fact]
        public void LoadMinimalConfig_Success()
        {
            var services = new ServiceCollection();
            ServiceCollectionExtensions.ConfigureApplicationServices(services, new LoggingLevelSwitch(Serilog.Events.LogEventLevel.Information), null);
            var provider = services.BuildServiceProvider();

            var adapterService = provider.GetRequiredService<AdapterService>();
            adapterService.StartServer();
        }
    }
}