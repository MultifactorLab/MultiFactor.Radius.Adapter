//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Services.Ldap;
using System;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    /// <summary>
    /// Membership verification result for the specified domain.
    /// </summary>
    public class MembershipVerificationResult
    {
        /// <summary>
        /// Domain for which the membership verification was performed.
        /// </summary>
        public LdapIdentity Domain { get; }

        /// <summary>
        /// Verification is successfully complete.
        /// </summary>
        public bool IsSuccess { get; private set; }

        public bool IsMemberOf2FaGroups { get; private set; }

        public bool IsMemberOf2FaBypassGroup { get; private set; }

        /// <summary>
        /// User profile from the current domain.
        /// </summary>
        public LdapProfile Profile { get; private set; }

        protected MembershipVerificationResult(LdapIdentity domain)
        {
            Domain = domain;
        }

        public static MembershipVerificationResultBuilder Create(LdapIdentity domain)
        {
            if (domain is null) throw new ArgumentNullException(nameof(domain));
            return new MembershipVerificationResultBuilder(new MembershipVerificationResult(domain));
        }

        public class MembershipVerificationResultBuilder
        {
            private readonly MembershipVerificationResult _result;
            public MembershipVerificationResult Subject => _result;

            public MembershipVerificationResultBuilder(MembershipVerificationResult result)
            {
                _result = result;
            }

            public MembershipVerificationResultBuilder SetSuccess(bool success)
            {
                _result.IsSuccess = success;
                return this;
            }

            public MembershipVerificationResultBuilder SetProfile(LdapProfile profile)
            {
                _result.Profile = profile;
                return this;
            }
            
            public MembershipVerificationResultBuilder SetIsMemberOf2FaGroups(bool isMemberOf)
            {
                _result.IsMemberOf2FaGroups = isMemberOf;
                return this;
            }
            
            public MembershipVerificationResultBuilder SetIsMemberOf2FaBypassGroup(bool isMemberOf)
            {
                _result.IsMemberOf2FaBypassGroup = isMemberOf;
                return this;
            }

            public MembershipVerificationResult Build()
            {
                return _result;
            }
        }
    }
}