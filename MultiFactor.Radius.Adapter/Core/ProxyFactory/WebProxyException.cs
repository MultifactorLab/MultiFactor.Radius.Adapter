using System;

namespace MultiFactor.Radius.Adapter.Core
{
    [Serializable]
    internal class WebProxyException : Exception
    {
        public WebProxyException() { }
        public WebProxyException(string message) : base(message) { }
        public WebProxyException(string message, Exception inner) : base(message, inner) { }
        protected WebProxyException(
            System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}