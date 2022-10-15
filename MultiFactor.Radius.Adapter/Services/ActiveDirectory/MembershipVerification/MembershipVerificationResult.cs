//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Services.Ldap;
using System;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    public class MembershipVerificationResult
    {
        public LdapIdentity Domain { get; }
        public bool IsSuccess { get; private set; }
        public bool Bypass2Fa { get; private set; }
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

            public MembershipVerificationResultBuilder SetBypass2Fa(bool bypass2Fa)
            {
                _result.Bypass2Fa = bypass2Fa;
                return this;
            }

            public MembershipVerificationResult Build()
            {
                return _result;
            }
        }
    }
}