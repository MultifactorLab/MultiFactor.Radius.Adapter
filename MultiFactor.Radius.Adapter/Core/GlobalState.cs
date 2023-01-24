using MultiFactor.Radius.Adapter.Core.ApplicationOptions;
using System;

namespace MultiFactor.Radius.Adapter.Core
{
    public static class GlobalState
    {
        public static IApplicationRunOptions RunOptions { get; private set; } = ApplicationRunOptions.Empty;
        public static void SetRunOptions(IApplicationRunOptions runOptions)
        {
            if (runOptions is null) throw new ArgumentNullException(nameof(runOptions));
            RunOptions = runOptions;
        }
    }
}
