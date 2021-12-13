//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

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
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using MultiFactor.Radius.Adapter.Services;

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
        private CacheService _cacheService;

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

            _cacheService = new CacheService(_logger);

            _localEndpoint = configuration.ServiceServerEndpoint;
            _router = new RadiusRouter(configuration, radiusPacketParser, _cacheService, logger);
        }

        /// <summary>
        /// Start listening for requests
        /// </summary>
        public void Start()
        {
            if (!Running)
            {
                _logger.Information("Starting Radius server on {host:l}:{port}", _localEndpoint.Address, _localEndpoint.Port);
               
                _server = new UdpClient(_localEndpoint);
                Running = true;
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
                var handlersCount = Interlocked.Increment(ref _concurrentHandlerCount);
                _logger.Verbose("Received packet from {host:l}:{port}, Concurrent handlers count: {handlersCount}", remoteEndpoint.Address, remoteEndpoint.Port, handlersCount);
                ParseAndProcess(packetBytes, remoteEndpoint);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is OverflowException)
            {
                _logger.Warning(ex, "Ignoring malformed(?) packet received from {host}:{port}", remoteEndpoint.Address, remoteEndpoint.Port);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to receive packet from {host:l}:{port}", remoteEndpoint.Address, remoteEndpoint.Port);
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
            IPEndPoint proxyEndpoint = null;

            if (IsProxyProtocol(packetBytes, out var sourceEndpoint, out var requestWithoutProxyHeader))
            {
                packetBytes = requestWithoutProxyHeader;
                proxyEndpoint = remoteEndpoint;
                remoteEndpoint = sourceEndpoint;
            }

            var requestPacket = _radiusPacketParser.Parse(packetBytes, Encoding.UTF8.GetBytes(_configuration.RadiusSharedSecret));
            var isRetransmission = _cacheService.IsRetransmission(requestPacket, remoteEndpoint);

            if (!isRetransmission)
            {
                if (proxyEndpoint != null)
                {
                    if (requestPacket.Code == PacketCode.StatusServer)
                    {
                        _logger.Information("Received {code:l} from {host:l}:{port} proxied by {proxyhost:l}:{proxyport} id={id}", requestPacket.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, proxyEndpoint.Address, proxyEndpoint.Port, requestPacket.Identifier);
                    }
                    else
                    {
                        _logger.Information("Received {code:l} from {host:l}:{port} proxied by {proxyhost:l}:{proxyport} id={id} user='{user:l}'", requestPacket.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, proxyEndpoint.Address, proxyEndpoint.Port, requestPacket.Identifier, requestPacket.UserName);
                    }
                }
                else
                {
                    if (requestPacket.Code == PacketCode.StatusServer)
                    {
                        _logger.Debug("Received {code:l} from {host:l}:{port} id={id}", requestPacket.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, requestPacket.Identifier);
                    }
                    else
                    {
                        _logger.Information("Received {code:l} from {host:l}:{port} id={id} user='{user:l}'", requestPacket.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, requestPacket.Identifier, requestPacket.UserName);
                    }
                }
            }

            if (isRetransmission)
            {
                _logger.Debug("Retransmissed request from {host:l}:{port} id={id}, ignoring", remoteEndpoint.Address, remoteEndpoint.Port, requestPacket.Identifier);
                return;
            }

            var request = new PendingRequest { RemoteEndpoint = remoteEndpoint, ProxyEndpoint = proxyEndpoint, RequestPacket = requestPacket };

            Task.Run(() => _router.HandleRequest(request));
        }

        /// <summary>
        /// Sends a packet
        /// </summary>
        private void Send(IRadiusPacket responsePacket, string user, IPEndPoint remoteEndpoint, IPEndPoint proxyEndpoint, bool debugLog)
        {
            var responseBytes = _radiusPacketParser.GetBytes(responsePacket);
            _server.Send(responseBytes, responseBytes.Length, proxyEndpoint ?? remoteEndpoint);

            if (proxyEndpoint != null)
            {
                if (debugLog)
                {
                    _logger.Debug("{code:l} sent to {host:l}:{port} via {proxyhost:l}:{proxyport} id={id}", responsePacket.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, proxyEndpoint.Address, proxyEndpoint.Port, responsePacket.Identifier);
                }
                else
                {
                    _logger.Information("{code:l} sent to {host:l}:{port} via {proxyhost:l}:{proxyport} id={id} user='{user:l}'", responsePacket.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, proxyEndpoint.Address, proxyEndpoint.Port, responsePacket.Identifier, user);
                }
            }
            else
            {
                if (debugLog)
                {
                    _logger.Debug("{code:l} sent to {host:l}:{port} id={id}", responsePacket.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, responsePacket.Identifier);
                }
                else
                {
                    _logger.Information("{code:l} sent to {host:l}:{port} id={id} user='{user:l}'", responsePacket.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, responsePacket.Identifier, user);
                }
            }
        }

        private void RouterRequestProcessed(object sender, PendingRequest request)
        {
            if (request.ResponsePacket?.IsEapMessageChallenge == true)
            {
                //EAP authentication in process, just proxy response
                _logger.Debug("Proxying EAP-Message Challenge to {host:l}:{port} id={id}", request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, request.RequestPacket.Identifier);
                Send(request.ResponsePacket, request.RequestPacket?.UserName, request.RemoteEndpoint, request.ProxyEndpoint, true);

                return; //stop processing
            }

            var requestPacket = request.RequestPacket;
            var responsePacket = requestPacket.CreateResponsePacket(request.ResponseCode);

            if (request.ResponseCode == PacketCode.AccessAccept)
            {
                if (request.ResponsePacket != null) //copy from remote radius reply
                {
                    request.ResponsePacket.CopyTo(responsePacket);
                }
                if (request.RequestPacket.Code == PacketCode.StatusServer)
                {
                    responsePacket.AddAttribute("Reply-Message", request.ReplyMessage);
                }
            }

            //proxy echo required
            if (!_configuration.RemoveProxyState)
            {
                if (requestPacket.Attributes.ContainsKey("Proxy-State"))
                {
                    if (!responsePacket.Attributes.ContainsKey("Proxy-State"))
                    {
                        responsePacket.Attributes.Add("Proxy-State", requestPacket.Attributes.SingleOrDefault(o => o.Key == "Proxy-State").Value);
                    }
                }
            }
            else
            {
                responsePacket.Attributes.Remove("Proxy-State");
            }


            if (request.ResponseCode == PacketCode.AccessChallenge)
            {
                responsePacket.AddAttribute("Reply-Message", request.ReplyMessage ?? "Enter OTP code: ");
                responsePacket.AddAttribute("State", request.State); //state to match user authentication session
            }

            //add custom reply attributes
            if (request.ResponseCode == PacketCode.AccessAccept)
            {
                foreach (var attr in _configuration.RadiusReplyAttributes)
                {
                    //check condition
                    var matched = attr.Value.Where(val => val.IsMatch(request)).Select(val => val.Value);
                    if (matched.Any())
                    {
                        responsePacket.Attributes.Add(attr.Key, matched.ToList());
                    }
                }
            }

            var debugLog = request.RequestPacket.Code == PacketCode.StatusServer;
            Send(responsePacket, request.RequestPacket?.UserName, request.RemoteEndpoint, request.ProxyEndpoint, debugLog);
        }

        private bool IsProxyProtocol(byte[] request, out IPEndPoint sourceEndpoint, out byte[] requestWithoutProxyHeader)
        {
            //https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

            sourceEndpoint = null;
            requestWithoutProxyHeader = null;

            if (request.Length < 6)
            {
                return false;
            }

            var proxySig = Encoding.ASCII.GetString(request.Take(5).ToArray());

            if (proxySig == "PROXY")
            {
                var lf = Array.IndexOf(request, (byte)'\n');
                var headerBytes = request.Take(lf + 1).ToArray();
                var header = Encoding.ASCII.GetString(headerBytes);

                var parts = header.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

                var sourceIp = parts[2];
                var sourcePort = int.Parse(parts[4]);

                sourceEndpoint = new IPEndPoint(IPAddress.Parse(sourceIp), sourcePort);
                requestWithoutProxyHeader = request.Skip(lf + 1).ToArray();

                return true;
            }

            return false;
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