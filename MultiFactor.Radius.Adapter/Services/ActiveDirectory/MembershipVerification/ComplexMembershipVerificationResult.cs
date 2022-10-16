//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System.Collections.Generic;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    /// <summary>
    /// Membership verification result for multiple domains.
    /// </summary>
    public class ComplexMembershipVerificationResult
    {
        private readonly List<MembershipVerificationResult> _list = new List<MembershipVerificationResult>();
        public IReadOnlyList<MembershipVerificationResult> Results => _list.AsReadOnly();

        /// <summary>
        /// Returns only successful results.
        /// </summary>
        public IReadOnlyList<MembershipVerificationResult> Succeeded => _list
            .Where(x => x.IsSuccess)
            .ToList()
            .AsReadOnly();

        /// <summary>
        /// Adds atomic verification result to a complex rsult.
        /// </summary>
        /// <param name="result">Verification result for the specified domain.</param>
        public void AddDomainResult(MembershipVerificationResult result)
        {
            _list.Add(result);
        }
    }
}