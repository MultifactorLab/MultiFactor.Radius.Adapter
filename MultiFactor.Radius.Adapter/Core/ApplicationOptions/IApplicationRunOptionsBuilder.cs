namespace MultiFactor.Radius.Adapter.Core.ApplicationOptions
{
    public interface IApplicationRunOptionsBuilder
    {
        IApplicationRunOptionsBuilder AddOption(RunOptionName name, string value);
        IApplicationRunOptions Build();
    }
}
