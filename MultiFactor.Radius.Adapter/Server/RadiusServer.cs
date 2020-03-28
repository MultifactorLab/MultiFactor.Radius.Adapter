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
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Collections.Concurrent;

namespace MultiFactor.Radius.Adapter.Server
{
    public sealed class RadiusServer : IDisposable
    {
        private UdpClient _server;
        private readonly IPEndPoint _localEndpoint;
        private readonly IRadiusPacketParser _radiusPacketParser;
        private int _concurrentHandlerCount = 0;
        private readonly ILogger _logger;
        private RadiusRouter _router;
        private Configuration _configuration;

        public bool Running
        {
            get;
            private set;
        }

        /// <summary>
        /// Create a new server on endpoint with packet handler repository
        /// </summary>
        public RadiusServer(Configuration configuration, IRadiusPacketParser radiusPacketParser, ILogger logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _radiusPacketParser = radiusPacketParser ?? throw new ArgumentNullException(nameof(radiusPacketParser));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _localEndpoint = configuration.ServiceServerEndpoint;
            _router = new RadiusRouter(configuration, radiusPacketParser, logger);
        }

        /// <summary>
        /// Start listening for requests
        /// </summary>
        public void Start()
        {
            if (!Running)
            {
                _server = new UdpClient(_localEndpoint);
                Running = true;
                _logger.Information($"Starting Radius server on {_localEndpoint}");
                var receiveTask = Receive();

                _router.RequestProcessed += RouterRequestProcessed;

                _logger.Information("Server started");
            }
            else
            {
                _logger.Warning("Server already started");
            }
        }

        /// <summary>
        /// Stop listening
        /// </summary>
        public void Stop()
        {
            if (Running)
            {
                _logger.Information("Stopping server");
                Running = false;
                _server?.Close();
                _router.RequestProcessed -= RouterRequestProcessed;
                _logger.Information("Stopped");
            }
            else
            {
                _logger.Warning("Server already stopped");
            }
        }

        /// <summary>
        /// Start the loop used for receiving packets
        /// </summary>
        /// <returns></returns>
        private async Task Receive()
        {
            while (Running)
            {
                try
                {
                    var response = await _server.ReceiveAsync();
                    var task = Task.Factory.StartNew(() => HandlePacket(response.RemoteEndPoint, response.Buffer), TaskCreationOptions.LongRunning);
                }
                catch (ObjectDisposedException) { } // This is thrown when udpclient is disposed, can be safely ignored
                catch (Exception ex)
                {
                    _logger.Error(ex, "Something went wrong receiving packet");
                }
            }
        }

        /// <summary>
        /// Used to handle the packets asynchronously
        /// </summary>
        /// <param name="remoteEndpoint"></param>
        /// <param name="packetBytes"></param>
        private void HandlePacket(IPEndPoint remoteEndpoint, byte[] packetBytes)
        {
            try
            {
                _logger.Debug($"Received packet from {remoteEndpoint}, Concurrent handlers count: {Interlocked.Increment(ref _concurrentHandlerCount)}");
                ParseAndProcess(packetBytes, remoteEndpoint);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is OverflowException)
            {
                _logger.Warning(ex, $"Ignoring malformed(?) packet received from {remoteEndpoint}");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Failed to receive packet from {remoteEndpoint}");
            }
            finally
            {
                Interlocked.Decrement(ref _concurrentHandlerCount);
            }
        }

        /// <summary>
        /// Parses a packet and gets a response packet from the handler
        /// </summary>
        internal void ParseAndProcess(byte[] packetBytes, IPEndPoint remoteEndpoint)
        {
            var requestPacket = _radiusPacketParser.Parse(packetBytes, Encoding.ASCII.GetBytes(_configuration.SharedSecret));

            _logger.Information($"Received {requestPacket.Code} from {remoteEndpoint} Id={requestPacket.Identifier}");

            var request = new PendingRequest { RemoteEndpoint = remoteEndpoint, Packet = requestPacket };

            Task.Run(() => _router.HandleRequest(request));
        }

        /// <summary>
        /// Sends a packet
        /// </summary>
        /// <param name="responsePacket"></param>
        /// <param name="remoteEndpoint"></param>
        private void Send(IRadiusPacket responsePacket, IPEndPoint remoteEndpoint)
        {
            var responseBytes = _radiusPacketParser.GetBytes(responsePacket);
            _server.Send(responseBytes, responseBytes.Length, remoteEndpoint);
            _logger.Information($"{responsePacket.Code} sent to {remoteEndpoint} Id={responsePacket.Identifier}");
        }

        private void RouterRequestProcessed(object sender, PendingRequest request)
        {
            var requestPacket = request.Packet;
            var responsePacket = requestPacket.CreateResponsePacket(request.ResponseCode);

            if (request.ResponseCode == PacketCode.AccessChallenge)
            {
                //OTP from user required to process
                responsePacket.AddAttribute("Reply-Message", "Enter OTP code");
                responsePacket.AddAttribute("State", request.State); //state to match user authentication session
            }
            if (requestPacket.Attributes.ContainsKey("Proxy-State"))
            {
                responsePacket.Attributes.Add("Proxy-State", requestPacket.Attributes.SingleOrDefault(o => o.Key == "Proxy-State").Value);
            }

            Send(responsePacket, request.RemoteEndpoint);
        }


        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            _server?.Close();
        }
    }
}