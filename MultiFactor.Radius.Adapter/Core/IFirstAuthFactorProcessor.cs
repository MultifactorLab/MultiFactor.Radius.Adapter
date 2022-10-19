//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Server;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Core
{
    public interface IFirstAuthFactorProcessor
    {
        /// <summary>
        /// Returns auth sources supported by the current processor implementation.
        /// </summary>
        AuthenticationSource AuthenticationSource { get; }
        Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request, ClientConfiguration clientConfig);
    }
}