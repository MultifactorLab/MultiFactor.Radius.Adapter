namespace MultiFactor.Radius.Adapter.Core.ApplicationOptions
{
    public interface IApplicationRunOptions
    {
        bool HasOption(RunOptionName name);
        RunOption GetOption(RunOptionName name);
    }
}
