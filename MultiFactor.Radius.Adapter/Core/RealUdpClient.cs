using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Core
{
    internal class RealUdpClient : IUdpClient
    {
        private readonly UdpClient _udpClient;

        public RealUdpClient(IPEndPoint endpoint)
        {
            if (endpoint is null)
            {
                throw new ArgumentNullException(nameof(endpoint));
            }

            _udpClient = new UdpClient(endpoint);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Close() => _udpClient.Close();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Task<UdpReceiveResult> ReceiveAsync() => _udpClient.ReceiveAsync();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int Send(byte[] dgram, int bytes, IPEndPoint endPoint) => _udpClient.Send(dgram, bytes, endPoint);
    }
}
