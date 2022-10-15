//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using System;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    public class MembershipVerificationResultHandler
    {
        private readonly ComplexMembershipVerificationResult _verificationResult;

        public MembershipVerificationResultHandler(ComplexMembershipVerificationResult verificationResult)
        {
            _verificationResult = verificationResult ?? throw new ArgumentNullException(nameof(verificationResult));
        }

        public PacketCode GetDecision()
        {
            return _verificationResult.Succeeded.Any()
                ? PacketCode.AccessAccept
                : PacketCode.AccessReject;
        }

        public void EnrichRequest(PendingRequest request)
        {
            var profile = _verificationResult.Succeeded.Select(x => x.Profile).FirstOrDefault(x => x != null);

            request.Bypass2Fa = _verificationResult.Succeeded.All(x => x.Bypass2Fa);
            request.Upn = profile.Upn;
            request.DisplayName = profile.DisplayName;
            request.EmailAddress = profile.Email;
            request.UserPhone = profile.Phone;
            request.LdapAttrs = profile.LdapAttrs;

            if (profile.MemberOf != null)
            {
                request.UserGroups = profile.MemberOf;
            }
        }
    }
}