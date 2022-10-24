//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md


using System;

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi
{
    [Serializable]
    internal class MultifactorApiUnreachableException : Exception
    {
        public MultifactorApiUnreachableException() { }
        public MultifactorApiUnreachableException(string message) : base(message) { }
        public MultifactorApiUnreachableException(string message, Exception inner) : base(message, inner) { }
        protected MultifactorApiUnreachableException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}
