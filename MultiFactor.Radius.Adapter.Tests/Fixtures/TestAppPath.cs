using MultiFactor.Radius.Adapter.Core;

namespace MultiFactor.Radius.Adapter.Tests.Fixtures
{
    internal class TestAppPath : IApplicationPath
    {
        public string GetApplicationPath() => Constants.ApplicationPath;
    }
}
