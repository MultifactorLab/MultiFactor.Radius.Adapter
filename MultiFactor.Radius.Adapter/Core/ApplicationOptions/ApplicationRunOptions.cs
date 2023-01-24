using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Core.ApplicationOptions
{
    public class ApplicationRunOptions : IApplicationRunOptions, IApplicationRunOptionsBuilder
    {
        private readonly Dictionary<RunOptionName, RunOption> _runOptions = new Dictionary<RunOptionName, RunOption>();

        public static ApplicationRunOptions Empty => new ApplicationRunOptions();

        private ApplicationRunOptions() { }

        public static IApplicationRunOptionsBuilder CreateBuilder() => new ApplicationRunOptions();

        public IApplicationRunOptionsBuilder AddOption(RunOptionName name, string value)
        {
            _runOptions[name] = new RunOption(name, value);
            return this;
        }

        public IApplicationRunOptions Build() => this;

        public RunOption GetOption(RunOptionName name) => _runOptions[name];

        public bool HasOption(RunOptionName name) => _runOptions.ContainsKey(name);
    }
}
