//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System.Collections.Generic;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    public class ComplexMembershipVerificationResult
    {
        private readonly List<MembershipVerificationResult> _list = new List<MembershipVerificationResult>();
        public IReadOnlyList<MembershipVerificationResult> Results => _list.AsReadOnly();

        public IReadOnlyList<MembershipVerificationResult> Succeeded => _list
            .Where(x => x.IsSuccess)
            .ToList()
            .AsReadOnly();

        public void AddDomainResult(MembershipVerificationResult result)
        {
            _list.Add(result);
        }
    }
}