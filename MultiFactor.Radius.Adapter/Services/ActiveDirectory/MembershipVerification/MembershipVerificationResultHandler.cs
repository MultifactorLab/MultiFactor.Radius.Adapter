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

        /// <summary>
        /// Returns Accept or Reject code as an overall result of multiple verification results.
        /// </summary>
        /// <returns><see cref="PacketCode.AccessAccept"/> or <see cref="PacketCode.AccessReject"/></returns>
        public PacketCode GetDecision()
        {
            return _verificationResult.Succeeded.Any()
                ? PacketCode.AccessAccept
                : PacketCode.AccessReject;
        }

        /// <summary>
        /// Sets some request's property values.
        /// </summary>
        /// <param name="request">Pending request.</param>
        public void EnrichRequest(PendingRequest request)
        {
            var profile = _verificationResult.Succeeded.Select(x => x.Profile).FirstOrDefault(x => x != null);
            if (profile == null) return;

            request.Bypass2Fa = IsBypassed();
            request.UpdateProfile(profile);

            if (profile.MemberOf.Count != 0)
            {
                request.UserGroups = profile.MemberOf;
            }
        }

        private bool IsBypassed()
        {
            var succeeded = _verificationResult.Succeeded.ToList();

            if (!succeeded.Any()) return false;
            if (succeeded.Any(x => x.IsMemberOf2FaBypassGroup)) return true;
            if (succeeded.Any(x => x.Are2FaGroupsSpecified && !x.IsMemberOf2FaGroups)) return true;

            return false;
        }
    }
}