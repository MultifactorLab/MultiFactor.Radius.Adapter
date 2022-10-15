//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    [Serializable]
    internal class UserDomainNotPermittedException : Exception
    {
        public UserDomainNotPermittedException() { }
        public UserDomainNotPermittedException(string message) : base(message) { }
        public UserDomainNotPermittedException(string message, Exception inner) : base(message, inner) { }
        protected UserDomainNotPermittedException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}