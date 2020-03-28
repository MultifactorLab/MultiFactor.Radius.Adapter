using MultiFactor.Radius.Adapter.Core;
using System;
using System.Net;

namespace MultiFactor.Radius.Adapter.Server
{
    public class PendingRequest
    {
        public PendingRequest()
        {
            ReceivedAt = DateTime.Now;
            ResponseCode = PacketCode.AccessReject;
        }
        public IPEndPoint RemoteEndpoint { get; set; }
        public IRadiusPacket Packet { get; set; }
        public DateTime ReceivedAt { get; set; }
        public PacketCode ResponseCode { get; set; }
        public string State { get; set; }
    }
}
