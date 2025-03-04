﻿//Copyright(c) 2020 MultiFactor
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
using MultiFactor.Radius.Adapter.Services;
using System.Globalization;
using System.Collections.Generic;
using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Logging;

namespace MultiFactor.Radius.Adapter.Server
{
    public sealed class RadiusServer : IDisposable
    {
        private IUdpClient _server;
        private IRadiusResponseSender _responseSender;

        private readonly IPEndPoint _localEndpoint;
        private readonly IRadiusPacketParser _radiusPacketParser;
        private readonly IRadiusDictionary _dictionary;
        private int _concurrentHandlerCount = 0;
        private readonly ILogger _logger;
        private readonly ServiceConfiguration _serviceConfiguration;
        private readonly CacheService _cacheService;
        private readonly RadiusRouter _radiusRouter;

        private readonly Func<IPEndPoint, IUdpClient> _createUdpClient;

        public bool Running
        {
            get;
            private set;
        }

        /// <summary>
        /// Create a new server on endpoint with packet handler repository
        /// </summary>
        public RadiusServer(ServiceConfiguration serviceConfiguration, 
            IRadiusDictionary dictionary, 
            IRadiusPacketParser radiusPacketParser,
            CacheService cacheService,
            RadiusRouter radiusRouter,
            // need for tests only
            Func<IPEndPoint, IUdpClient> createUdpClient,
            IRadiusResponseSender responseSender,
            ILogger logger)
        {
            _serviceConfiguration = serviceConfiguration ?? throw new ArgumentNullException(nameof(serviceConfiguration));
            _dictionary = dictionary ?? throw new ArgumentNullException(nameof(dictionary));
            _radiusPacketParser = radiusPacketParser ?? throw new ArgumentNullException(nameof(radiusPacketParser));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _radiusRouter = radiusRouter ?? throw new ArgumentNullException(nameof(radiusRouter));
            _createUdpClient = createUdpClient;
            _responseSender = responseSender;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _localEndpoint = serviceConfiguration.ServiceServerEndpoint;
        }

        /// <summary>
        /// Start listening for requests
        /// </summary>
        public void Start()
        {
            if (!Running)
            {
                _logger.Information("Starting Radius server on {host:l}:{port}", _localEndpoint.Address, _localEndpoint.Port);
               
                _server = _createUdpClient(_localEndpoint);

                Running = true;
                var receiveTask = Receive();

                _radiusRouter.RequestProcessed += RouterRequestProcessed;
                _radiusRouter.RequestWillNotBeProcessed += RouterRequestWillNotBeProcessed;

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
                _radiusRouter.RequestProcessed -= RouterRequestProcessed;
                _radiusRouter.RequestWillNotBeProcessed -= RouterRequestWillNotBeProcessed;
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
                    _logger.Error(ex, "Something went wrong transmitting packet: {msg:l}", ex.Message);
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
                _logger.Warning(ex, "Ignoring malformed(?) packet received from {host}:{port}, message: {msg:l}", remoteEndpoint.Address, remoteEndpoint.Port, ex.Message);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to receive packet from {host:l}:{port}, message: {msg:l}", remoteEndpoint.Address, remoteEndpoint.Port, ex.Message);
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

            ClientConfiguration clientConfiguration = null;
            if (RadiusPacketNasIdentifierParser.TryParse(packetBytes, out var nasIdentifier))
            {
                clientConfiguration = _serviceConfiguration.GetClient(nasIdentifier);
            }
            if (clientConfiguration == null)
            {
                clientConfiguration = _serviceConfiguration.GetClient(remoteEndpoint.Address);
            }

            if (clientConfiguration == null)
            {
                _logger.Warning("Received packet from unknown client {host:l}:{port}, ignoring", remoteEndpoint.Address, remoteEndpoint.Port);
                return;
            }

            var requestPacket = _radiusPacketParser.Parse(packetBytes, 
                new SharedSecret(clientConfiguration.RadiusSharedSecret), 
                encodingName: clientConfiguration.RadiusPapEncoding,
                configure: x => x.CallingStationIdAttribute = clientConfiguration.CallingStationIdVendorAttribute);
            var requestScope = new RequestScope(clientConfiguration, remoteEndpoint, proxyEndpoint, requestPacket);

            LoggerScope.Wrap(ProcessRequest, requestScope);
        }

        private void ProcessRequest(RequestScope requestScope)
        {
            var isRetransmission = _cacheService.IsRetransmission(requestScope.Packet, requestScope.RemoteEndpoint);
            if (isRetransmission)
            {
                _logger.Debug("Retransmissed request from {host:l}:{port} id={id} client '{client:l}', ignoring", 
                    requestScope.RemoteEndpoint.Address, 
                    requestScope.RemoteEndpoint.Port, 
                    requestScope.Packet.Header.Identifier, 
                    requestScope.ClientConfiguration.Name);
                return;
            }

            if (requestScope.ProxyEndpoint != null)
            {
                if (requestScope.Packet.Header.Code == PacketCode.StatusServer)
                {
                    _logger.Information("Received {code:l} from {host:l}:{port} proxied by {proxyhost:l}:{proxyport} id={id} client '{client:l}'",  
                        requestScope.Packet.Header.Code.ToString(), 
                        requestScope.RemoteEndpoint.Address, 
                        requestScope.RemoteEndpoint.Port, 
                        requestScope.ProxyEndpoint.Address, 
                        requestScope.ProxyEndpoint.Port, 
                        requestScope.Packet.Header.Identifier, 
                        requestScope.ClientConfiguration.Name);
                }
                else
                {
                    _logger.Information("Received {code:l} from {host:l}:{port} proxied by {proxyhost:l}:{proxyport} id={id} user='{user:l}' client '{client:l}'", 
                        requestScope.Packet.Header.Code.ToString(), 
                        requestScope.RemoteEndpoint.Address, 
                        requestScope.RemoteEndpoint.Port, 
                        requestScope.ProxyEndpoint.Address, 
                        requestScope.ProxyEndpoint.Port, 
                        requestScope.Packet.Header.Identifier, 
                        requestScope.Packet.UserName, 
                        requestScope.ClientConfiguration.Name);
                }
            }
            else
            {
                if (requestScope.Packet.Header.Code == PacketCode.StatusServer)
                {
                    _logger.Debug("Received {code:l} from {host:l}:{port} id={id} client '{client:l}'", 
                        requestScope.Packet.Header.Code.ToString(), 
                        requestScope.RemoteEndpoint.Address, 
                        requestScope.RemoteEndpoint.Port, 
                        requestScope.Packet.Header.Identifier, 
                        requestScope.ClientConfiguration.Name);
                }
                else
                {
                    _logger.Information("Received {code:l} from {host:l}:{port} id={id} user='{user:l}' client '{client:l}'", 
                        requestScope.Packet.Header.Code.ToString(), 
                        requestScope.RemoteEndpoint.Address, 
                        requestScope.RemoteEndpoint.Port, 
                        requestScope.Packet.Header.Identifier, 
                        requestScope.Packet.UserName, 
                        requestScope.ClientConfiguration.Name);
                }
            }

            var request = requestScope.CreatePendingRequest();
            Task.Run(async () => await _radiusRouter.HandleRequest(request));
        }

        /// <summary>
        /// Sends a packet
        /// </summary>
        private void Send(IRadiusPacket responsePacket, string user, IPEndPoint remoteEndpoint, IPEndPoint proxyEndpoint, bool debugLog)
        {
            _responseSender.Send(_server, responsePacket, proxyEndpoint ?? remoteEndpoint);

            if (proxyEndpoint != null)
            {
                if (debugLog)
                {
                    _logger.Debug("{code:l} sent to {host:l}:{port} via {proxyhost:l}:{proxyport} id={id}", responsePacket.Header.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, proxyEndpoint.Address, proxyEndpoint.Port, responsePacket.Header.Identifier);
                }
                else
                {
                    _logger.Information("{code:l} sent to {host:l}:{port} via {proxyhost:l}:{proxyport} id={id} user='{user:l}'", responsePacket.Header.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, proxyEndpoint.Address, proxyEndpoint.Port, responsePacket.Header.Identifier, user);
                }

                return;
            }
               
            if (debugLog)
            {
                _logger.Debug("{code:l} sent to {host:l}:{port} id={id}", responsePacket.Header.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, responsePacket.Header.Identifier);
                return;
            }
                  
            _logger.Information("{code:l} sent to {host:l}:{port} id={id} user='{user:l}'", responsePacket.Header.Code.ToString(), remoteEndpoint.Address, remoteEndpoint.Port, responsePacket.Header.Identifier, user); 
        }

        private async void RouterRequestProcessed(object sender, PendingRequest request)
        {
            if (request.ResponsePacket?.IsEapMessageChallenge == true)
            {
                //EAP authentication in process, just proxy response
                _logger.Debug("Proxying EAP-Message Challenge to {host:l}:{port} id={id}", request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, request.RequestPacket.Header.Identifier);
                Send(request.ResponsePacket, request.RequestPacket?.UserName, request.RemoteEndpoint, request.ProxyEndpoint, true);

                return; //stop processing
            }

            if (request.RequestPacket.IsVendorAclRequest == true && request.ResponsePacket != null)
            {
                //ACL and other rules transfer, just proxy response
                _logger.Debug("Proxying #ACSACL# to {host:l}:{port} id={id}", request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, request.RequestPacket.Header.Identifier);
                Send(request.ResponsePacket, request.RequestPacket?.UserName, request.RemoteEndpoint, request.ProxyEndpoint, true);

                return; //stop processing
            }

            var requestPacket = request.RequestPacket;
            var responsePacket = requestPacket.CreateResponsePacket(request.ResponseCode);

            switch (request.ResponseCode)
            {
                case PacketCode.AccessAccept:
                    if (request.ResponsePacket != null) //copy from remote radius reply
                    {
                        request.ResponsePacket.CopyTo(responsePacket);
                    }
                    if (request.RequestPacket.Header.Code == PacketCode.StatusServer)
                    {
                        responsePacket.AddAttribute("Reply-Message", request.ReplyMessage);
                    }

                    // TODO maybe request.Configuration instead of .GetClient()?
                    var clientConfiguration = _serviceConfiguration.GetClient(request);

                    if (request.ResponseCode == PacketCode.AccessAccept)
                    {
                        AddCustomReplyAttributes(request, responsePacket, clientConfiguration);
                    }

                    break;
                case PacketCode.AccessChallenge:
                    responsePacket.AddAttribute("Reply-Message", request.ReplyMessage ?? "Enter OTP code: ");
                    responsePacket.AddAttribute("State", request.State); //state to match user authentication session

                    break;
                case PacketCode.AccessReject:
                    if (request.ResponsePacket != null) //copy from remote radius reply
                    {
                        if (request.ResponsePacket.Header.Code == PacketCode.AccessReject) //for mschap pwd change only
                        {
                            request.ResponsePacket.CopyTo(responsePacket);
                        }
                    }
                    await new RandomWaiter(request.Configuration.InvalidCredentialDelay).WaitSomeTimeAsync();
                    break;
                default:
                    throw new NotImplementedException(request.ResponseCode.ToString());
            }

            //proxy echo required
            if (requestPacket.Attributes.ContainsKey("Proxy-State"))
            {
                if (!responsePacket.Attributes.ContainsKey("Proxy-State"))
                {
                    responsePacket.Attributes.Add("Proxy-State", requestPacket.Attributes.SingleOrDefault(o => o.Key == "Proxy-State").Value);
                }
            }
            
            // page 12  https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/51019988-746d-11ef-8355-fa163e15d75b/fortios-v7.2.10-release-notes.pdf
            if (!responsePacket.Attributes.ContainsKey("Message-Authenticator"))
            {
                var placeholder = new byte[16];
                var placeholderStr = Encoding.Default.GetString(placeholder);
                responsePacket.AddAttribute("Message-Authenticator", placeholderStr);
            }

            var debugLog = request.RequestPacket.Header.Code == PacketCode.StatusServer;
            Send(responsePacket, request.RequestPacket?.UserName, request.RemoteEndpoint, request.ProxyEndpoint, debugLog);
        }

        private void RouterRequestWillNotBeProcessed(object sender, PendingRequest request) { }

        private void AddCustomReplyAttributes(PendingRequest request, IRadiusPacket responsePacket, ClientConfiguration clientConfiguration)
        {
            foreach (var attr in clientConfiguration.RadiusReplyAttributes)
            {
                var breakLoop = false;
                var convertedValues = new List<object>();

                foreach (var attrElement in attr.Value)
                {
                    // check condition
                    if (!attrElement.IsMatch(request)) continue;

                    foreach (var val in attrElement.GetValues(request))
                    {
                        _logger.Debug("Added/replaced attribute '{attrname:l}:{attrval:l}' to reply", attr.Key, val.ToString());
                        convertedValues.Add(ConvertType(attr.Key, val));
                    }

                    if (attrElement.Sufficient)
                    {
                        breakLoop = true;
                        break;
                    }
                }

                responsePacket.Attributes[attr.Key] = convertedValues;
                if (breakLoop) break;
            }
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

        private object ConvertType(string attrName, object value)
        {
            if (value is string)
            {
                var stringValue = (string)value;
                var attribute = _dictionary.GetAttribute(attrName);
                switch (attribute.Type)
                {
                    case "ipaddr":
                        if (IPAddress.TryParse(stringValue, out var ipValue))
                        {
                            return ipValue;
                        }
                        
                        // maybe it is msRADIUSFramedIPAddress value
                        if (int.TryParse(stringValue, out var val))
                        {
                            return MsRadiusFramedIpAddressToIpAddress(val);
                        }

                        break;
                    case "date":
                        if (DateTime.TryParse(stringValue, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dateValue))
                        {
                            return dateValue;
                        }
                        break;
                    case "integer":
                        if (int.TryParse(stringValue, out var integerValue))
                        {
                            return integerValue;
                        }
                        break;
                }
            }

            return value;
        }

        private IPAddress MsRadiusFramedIpAddressToIpAddress(int intValue)
        {
            long longValue = intValue;
            
            // Microsoft subtracts 4294967296 from numbers above 2147483647 to
            // make them negative to make it, sort of, unsigned.
            // https://document.phenixid.net/m/90910/l/1601121-how-to-setup-framed-ip-using-ad-with-msradiusframedipaddress-attribute
            if (longValue < 0)
            {
                longValue += 4294967296;
            }
            
            var bytes = BitConverter.GetBytes(longValue).Take(4).ToArray();
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            return new IPAddress(bytes);
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