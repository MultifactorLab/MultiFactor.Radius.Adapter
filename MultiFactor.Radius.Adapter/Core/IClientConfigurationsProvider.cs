using System.Collections.ObjectModel;
using Config = System.Configuration.Configuration;

namespace MultiFactor.Radius.Adapter.Core
{
    public interface IClientConfigurationsProvider
    {
        ReadOnlyCollection<Config> GetClientConfigurations();
    }
}
