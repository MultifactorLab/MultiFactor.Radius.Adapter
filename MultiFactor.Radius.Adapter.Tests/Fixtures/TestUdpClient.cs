using MultiFactor.Radius.Adapter.Core;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Tests.Fixtures
{
    public class TestUdpClient : IUdpClient
    {
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly IPEndPoint _endpoint;
        private byte[] _dgram;
        private byte[] _sentDgram;

        public TestUdpClient(IPEndPoint endpoint)
        {
            _endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
        }

        public void Close() => _cts.Cancel();

        public Task<UdpReceiveResult> ReceiveAsync()
        {
            return Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested && _dgram == null)
                {
                    await Task.Delay(5, _cts.Token);
                }

                var arr = _dgram;
                _dgram = null;

                return new UdpReceiveResult(arr, _endpoint);
            }, _cts.Token);
        }

        public int Send(byte[] dgram, int bytes, IPEndPoint endPoint)
        {
            if (dgram is null)
            {
                throw new ArgumentNullException(nameof(dgram));
            }

            _sentDgram = dgram;
            return -1;
        }

        public async Task<byte[]> GetSentDataAsync()
        {
            while (!_cts.IsCancellationRequested && _sentDgram == null)
            {
                await Task.Delay(5, _cts.Token);
            }
            var arr = _sentDgram;
            _sentDgram = null;

            return arr;
        }

        public void SetDatagram(byte[] dgram)
        {
            _dgram = dgram ?? throw new ArgumentNullException(nameof(dgram));
        }
    }
}
