namespace MultiFactor.Radius.Adapter.Core
{
    internal class DefaultApplicationPath : IApplicationPath
    {
        public string GetApplicationPath() => Constants.ApplicationPath;
    }
}
