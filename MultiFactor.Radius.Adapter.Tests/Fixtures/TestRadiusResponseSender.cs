using MultiFactor.Radius.Adapter.Core;
using System.Net;

namespace MultiFactor.Radius.Adapter.Tests.Fixtures
{
    public class TestRadiusResponseSender : IRadiusResponseSender
    {
        private IRadiusPacket _responsePacket;
        public IRadiusPacket ResponsePacket => _responsePacket;

        public void Send(IUdpClient client, IRadiusPacket responsePacket, IPEndPoint remoteEndpoint)
        {
            _responsePacket = responsePacket;
        }
    }
}
