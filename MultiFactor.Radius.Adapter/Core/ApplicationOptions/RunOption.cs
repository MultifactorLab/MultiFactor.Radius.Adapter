namespace MultiFactor.Radius.Adapter.Core.ApplicationOptions
{
    public class RunOption
    {
        public RunOptionName Name { get; }
        public string Value { get; }

        public RunOption(RunOptionName name, string value)
        {
            Name = name;
            Value = value;
        }
    }
}
