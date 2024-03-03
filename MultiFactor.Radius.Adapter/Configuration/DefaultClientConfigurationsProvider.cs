using System.Collections.Generic;
using System;
using System.Collections.ObjectModel;
using System.Configuration;
using System.IO;
using Config = System.Configuration.Configuration;
using Serilog;
using MultiFactor.Radius.Adapter.Core;

namespace MultiFactor.Radius.Adapter.Configuration
{
    internal class DefaultClientConfigurationsProvider : IClientConfigurationsProvider
    {
        private readonly ILogger _logger;

        public DefaultClientConfigurationsProvider(ILogger logger)
        {
            _logger = logger;
        }

        public ReadOnlyCollection<Config> GetClientConfigurations()
        {
            var clientConfigFilesPath = $"{Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory)}{Path.DirectorySeparatorChar}clients";

            var clientConfigFiles = Directory.Exists(clientConfigFilesPath)
                ? Directory.GetFiles(clientConfigFilesPath, "*.config")
                : new string[0];

            if (clientConfigFiles.Length == 0)
            {
                return new ReadOnlyCollection<Config>(new Config[0]);
            }

            var list = new List<Config>();
            foreach (var file in clientConfigFiles)
            {
                _logger.Information("Loading client configuration from {ConfigFile:l}",
                    Path.GetFileName(file));

                var customConfigFileMap = new ExeConfigurationFileMap
                {
                    ExeConfigFilename = file
                };
                list.Add(ConfigurationManager.OpenMappedExeConfiguration(customConfigFileMap, ConfigurationUserLevel.None));
            }

            return new ReadOnlyCollection<Config>(list);
        }
    }
}
