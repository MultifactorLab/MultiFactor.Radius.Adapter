//MIT License

//Copyright(c) 2017 Verner Fortelius

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

using MultiFactor.Radius.Adapter.Core;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server
{
    public class RadiusClient : IDisposable
    {
        private readonly IPEndPoint _localEndpoint;
        private readonly UdpClient _udpClient;
        private readonly IRadiusPacketParser _radiusPacketParser;
        private readonly ConcurrentDictionary<Tuple<byte, IPEndPoint>, TaskCompletionSource<UdpReceiveResult>> _pendingRequests = new ConcurrentDictionary<Tuple<byte, IPEndPoint>, TaskCompletionSource<UdpReceiveResult>>();
        private readonly CancellationTokenSource _cancellationTokenSource;
        private readonly ILogger _logger;

        /// <summary>
        /// Create a radius client which sends and receives responses on localEndpoint
        /// </summary>
        /// <param name="localEndpoint"></param>
        /// <param name="dictionary"></param>
        public RadiusClient(IPEndPoint localEndpoint, IRadiusPacketParser radiusPacketParser, ILogger logger)
        {
            _localEndpoint = localEndpoint;
            _radiusPacketParser = radiusPacketParser;
            _logger = logger;
            _udpClient = new UdpClient(_localEndpoint);
            
            _cancellationTokenSource = new CancellationTokenSource();

            var receiveTask = StartReceiveLoopAsync(_cancellationTokenSource.Token);
        }


        /// <summary>
        /// Send a packet with specified timeout
        /// </summary>
        /// <param name="packet"></param>
        /// <param name="remoteEndpoint"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        public async Task<IRadiusPacket> SendPacketAsync(IRadiusPacket packet, IPEndPoint remoteEndpoint, TimeSpan timeout, byte[] originalUnpackedRequest = null)
        {
            var packetBytes = originalUnpackedRequest ?? _radiusPacketParser.GetBytes(packet);
            var responseTaskCS = new TaskCompletionSource<UdpReceiveResult>();

            if (_pendingRequests.TryAdd(new Tuple<byte, IPEndPoint>(packet.Identifier, remoteEndpoint), responseTaskCS))
            {
                await _udpClient.SendAsync(packetBytes, packetBytes.Length, remoteEndpoint);
                var completedTask = await Task.WhenAny(responseTaskCS.Task, Task.Delay(timeout));
                if (completedTask == responseTaskCS.Task)
                {
                    return _radiusPacketParser.Parse(responseTaskCS.Task.Result.Buffer, packet.SharedSecret);
                }

                //timeout
                _logger.Debug($"Server {remoteEndpoint.ToString()} did not respons within {timeout}");
                return null; 
            }

            _logger.Warning("Network error");
            return null;
        }

        /// <summary>
        /// Receive packets in a loop and complete tasks based on identifier
        /// </summary>
        /// <returns></returns>
        private async Task StartReceiveLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var response = await _udpClient.ReceiveAsync();

                    if (_pendingRequests.TryRemove(new Tuple<byte, IPEndPoint>(response.Buffer[1], response.RemoteEndPoint), out var taskCS))
                    {
                        taskCS.SetResult(response);
                    }
                }
                catch (ObjectDisposedException) 
                {
                    // This is thrown when udpclient is disposed, can be safely ignored
                }

                await Task.Delay(TimeSpan.FromMilliseconds(5));
            }
        }

        public void Dispose()
        {
            _cancellationTokenSource.Cancel();
            _udpClient?.Close();
        }
    }
}
