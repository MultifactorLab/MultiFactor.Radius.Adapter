using MultiFactor.Radius.Adapter.Core;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Configuration;
using System.IO;
using System.Linq;
using Config = System.Configuration.Configuration;

namespace MultiFactor.Radius.Adapter.Tests.Fixtures
{
    internal class TestClientConfigsProvider : IClientConfigurationsProvider
    {
        private readonly TestConfigProviderOptions _options;

        public TestClientConfigsProvider(Action<TestConfigProviderOptions> configure = null)
        {
            var opt = new TestConfigProviderOptions();
            configure?.Invoke(opt);
            _options = opt;
        }

        public ReadOnlyCollection<Config> GetClientConfigurations()
        {
            var clientConfigFiles = GetFiles().ToArray();
            if (clientConfigFiles.Length == 0)
            {
                return new ReadOnlyCollection<Config>(Array.Empty<Config>());
            }

            var list = new List<Config>();
            foreach (var file in clientConfigFiles)
            {
                var customConfigFileMap = new ExeConfigurationFileMap
                {
                    ExeConfigFilename = file
                };
                list.Add(ConfigurationManager.OpenMappedExeConfiguration(customConfigFileMap, ConfigurationUserLevel.None));
            }

            return new ReadOnlyCollection<Config>(list.ToArray());
        }

        private IEnumerable<string> GetFiles()
        {
            if (_options.ClientConfigFilePaths != null && _options.ClientConfigFilePaths.Length != 0)
            {
                foreach (var f in _options.ClientConfigFilePaths)
                {
                    if (File.Exists(f)) yield return f;
                }

                yield break;
            }

            if (string.IsNullOrWhiteSpace(_options.ClientConfigsFolderPath)) yield break;
            if (!Directory.Exists(_options.ClientConfigsFolderPath)) yield break;

            foreach (var f in Directory.GetFiles(_options.ClientConfigsFolderPath, "*.config"))
            {
                yield return f;
            }
        }
    }
}
