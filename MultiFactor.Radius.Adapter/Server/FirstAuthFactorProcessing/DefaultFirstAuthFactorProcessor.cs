//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using System;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    public class DefaultFirstAuthFactorProcessor : IFirstAuthFactorProcessor
    {
        private readonly ActiveDirectoryMembershipVerifier _membershipProcessor;

        public DefaultFirstAuthFactorProcessor(ActiveDirectoryMembershipVerifier membershipProcessor)
        {
            _membershipProcessor = membershipProcessor ?? throw new ArgumentNullException(nameof(membershipProcessor));
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.None;

        public Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request, ClientConfiguration clientConfig)
        {
            if (!clientConfig.CheckMembership)
            {
                return Task.FromResult(PacketCode.AccessAccept);
            }

            // check membership without AD authentication
            var result = _membershipProcessor.VerifyMembership(request, clientConfig);
            var handler = new MembershipVerificationResultHandler(result);

            handler.EnrichRequest(request);
            return Task.FromResult(handler.GetDecision());
        }
    }
}