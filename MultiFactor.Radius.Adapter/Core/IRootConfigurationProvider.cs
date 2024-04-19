using Config = System.Configuration.Configuration;

namespace MultiFactor.Radius.Adapter.Core
{
    public interface IRootConfigurationProvider
    {
        Config GetRootConfiguration();
    }
}
