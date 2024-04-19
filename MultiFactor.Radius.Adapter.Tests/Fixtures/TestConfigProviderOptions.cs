using System;

namespace MultiFactor.Radius.Adapter.Tests.Fixtures
{
    internal class TestConfigProviderOptions
    {
        public string RootConfigFilePath { get; set; }
        public string ClientConfigsFolderPath { get; set; }
        public string[] ClientConfigFilePaths { get; set; } = Array.Empty<string>();
    }
}
