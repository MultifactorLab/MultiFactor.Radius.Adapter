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
        private readonly ActiveDirectoryMembershipVerifier _membershipVerifier;

        public DefaultFirstAuthFactorProcessor(ActiveDirectoryMembershipVerifier membershipVerifier)
        {
            _membershipVerifier = membershipVerifier ?? throw new ArgumentNullException(nameof(membershipVerifier));
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.None;

        public Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request, ClientConfiguration clientConfig)
        {
            if (!clientConfig.CheckMembership)
            {
                return Task.FromResult(PacketCode.AccessAccept);
            }

            // check membership without AD authentication
            var result = _membershipVerifier.VerifyMembership(request, clientConfig);
            var handler = new MembershipVerificationResultHandler(result);

            handler.EnrichRequest(request);
            return Task.FromResult(handler.GetDecision());
        }
    }
}