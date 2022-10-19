//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification
{
    [Serializable]
    internal class UserNameFormatException : Exception
    {
        public UserNameFormatException() { }
        public UserNameFormatException(string message) : base(message) { }
        public UserNameFormatException(string message, Exception inner) : base(message, inner) { }
        protected UserNameFormatException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}