using MultiFactor.Radius.Adapter.Core;
using System;
using System.Configuration;
using Config = System.Configuration.Configuration;

namespace MultiFactor.Radius.Adapter.Tests.Fixtures
{
    internal class TestRootConfigProvider : IRootConfigurationProvider
    {
        private readonly TestConfigProviderOptions _options;

        public TestRootConfigProvider(Action<TestConfigProviderOptions> configure = null)
        {
            var opt = new TestConfigProviderOptions();
            configure?.Invoke(opt);
            _options = opt;
        }

        public Config GetRootConfiguration()
        {
            if (string.IsNullOrWhiteSpace(_options.RootConfigFilePath))
            {
                return ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            }

            var customConfigFileMap = new ExeConfigurationFileMap
            {
                ExeConfigFilename = _options.RootConfigFilePath
            };
            return ConfigurationManager.OpenMappedExeConfiguration(customConfigFileMap, ConfigurationUserLevel.None);
        }
    }
}
