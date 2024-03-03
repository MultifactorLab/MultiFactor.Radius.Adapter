using System.IO;

namespace MultiFactor.Radius.Adapter.Tests.Fixtures
{
    internal enum TestAssetLocation
    {
        RootConfigs,
        ClientConfigs,
        Packets
    }

    internal static class AssetsAccess
    {
        private static readonly string _appFolder = Constants.ApplicationPath;
        private static readonly string _assetsFolder = $"{_appFolder}{Path.DirectorySeparatorChar}Assets";

        public static string GetAssetPath(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return _assetsFolder;
            return $"{_assetsFolder}{Path.DirectorySeparatorChar}{fileName}";
        }

        public static string GetAssetPath(TestAssetLocation location)
        {
            switch (location)
            {
                case TestAssetLocation.Packets: 
                    return $"{_assetsFolder}{Path.DirectorySeparatorChar}Packets";

                case TestAssetLocation.ClientConfigs: 
                    return $"{_assetsFolder}{Path.DirectorySeparatorChar}Configs{Path.DirectorySeparatorChar}Clients";

                case TestAssetLocation.RootConfigs:
                    return $"{_assetsFolder}{Path.DirectorySeparatorChar}Configs";

                default:
                    return _assetsFolder;
            }
        }

        public static string GetAssetPath(TestAssetLocation location, string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return GetAssetPath(location);
            return $"{GetAssetPath(location)}{Path.DirectorySeparatorChar}{fileName}";
        }
    }
}
