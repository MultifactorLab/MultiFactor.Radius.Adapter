//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    public class FirstAuthFactorProcessorProvider
    {
        private readonly IEnumerable<IFirstAuthFactorProcessor> _processors;

        public FirstAuthFactorProcessorProvider(IEnumerable<IFirstAuthFactorProcessor> processors)
        {
            _processors = processors ?? throw new ArgumentNullException(nameof(processors));
        }

        public IFirstAuthFactorProcessor GetProcessor(AuthenticationSource authSource)
        {
            return _processors
                .FirstOrDefault(x => x.AuthenticationSource == authSource)
                ?? throw new NotImplementedException($"Unexpected authentication source '{authSource}'.");
        }
    }
}