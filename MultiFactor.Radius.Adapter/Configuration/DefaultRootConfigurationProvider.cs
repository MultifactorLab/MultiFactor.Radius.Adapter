using MultiFactor.Radius.Adapter.Core;
using System;
using System.Configuration;
using Config = System.Configuration.Configuration;

namespace MultiFactor.Radius.Adapter.Configuration
{
    internal class DefaultRootConfigurationProvider : IRootConfigurationProvider
    {
        private Lazy<Config> _rootConfig = new Lazy<Config>(() =>
        {
            return ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
        });

        public Config GetRootConfiguration()
        {
            return _rootConfig.Value;
        }
    }
}
