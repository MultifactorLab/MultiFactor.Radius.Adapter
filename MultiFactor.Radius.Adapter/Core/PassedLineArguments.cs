using System;
using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Core
{
    public enum KnownLineArg
    {
        ACT_AS_USER,
        ACT_AS_USER_PWD
    }

    public class PassedLineArguments
    {
        private readonly Dictionary<KnownLineArg, string> _arguments = new Dictionary<KnownLineArg, string>();

        public string this[KnownLineArg arg] => _arguments[arg];

        public bool Has(KnownLineArg arg) => _arguments.ContainsKey(arg);

        public PassedLineArguments(Dictionary<KnownLineArg, string> dict)
        {
            _arguments = dict ?? throw new ArgumentNullException(nameof(dict));
        }
    }
}
