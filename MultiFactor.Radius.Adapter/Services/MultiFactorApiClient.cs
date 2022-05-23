//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md


using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Services
{
    /// <summary>
    /// Service to interact with multifactor web api
    /// </summary>
    public class MultiFactorApiClient
    {
        private ServiceConfiguration _serviceConfiguration;
        private ILogger _logger;

        private static readonly ConcurrentDictionary<string, AuthenticatedClient> _authenticatedClients = new ConcurrentDictionary<string, AuthenticatedClient>();

        public MultiFactorApiClient(ServiceConfiguration serviceConfiguration, ILogger logger)
        {
            _serviceConfiguration = serviceConfiguration ?? throw new ArgumentNullException(nameof(serviceConfiguration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<PacketCode> CreateSecondFactorRequest(PendingRequest request, ClientConfiguration clientConfig)
        {
            var remoteHost = request.RequestPacket.RemoteHostName;
            var userName = request.UserName;
            var userPassword = request.RequestPacket.UserPassword;
            var displayName = request.DisplayName;
            var email = request.EmailAddress;
            var userPhone = request.UserPhone;
            var callingStationId = request.RequestPacket.CallingStationId;

            //try to get authenticated client to bypass second factor if configured
            if (clientConfig.BypassSecondFactorPeriod > 0)
            {
                if (TryHitCache(remoteHost, userName, clientConfig))
                {
                    _logger.Information("Bypass second factor for user '{user:l}' from {host:l}:{port}", userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                    return PacketCode.AccessAccept;
                }
            }
            
            var url = _serviceConfiguration.ApiUrl + "/access/requests/ra";
            var payload = new
            {
                Identity = userName,
                Name = displayName,
                Email = email,
                Phone = userPhone,
                PassCode = GetPassCodeOrNull(userPassword, clientConfig),
                CallingStationId = callingStationId,
                Capabilities = new 
                {
                    InlineEnroll = true
                }
            };

            var response = await SendRequest(url, payload, clientConfig);
            var responseCode = ConvertToRadiusCode(response);

            request.State = response?.Id;
            request.ReplyMessage = response?.ReplyMessage;

            if (responseCode == PacketCode.AccessAccept && !response.Bypassed)
            {
                _logger.Information("Second factor for user '{user:l}' verified successfully. Authenticator '{authenticator:l}', account '{account:l}'", userName, response?.Authenticator, response?.Account);

                if (clientConfig.BypassSecondFactorPeriod > 0)
                {
                    SetCache(remoteHost, userName);
                }
            }

            if (responseCode == PacketCode.AccessReject)
            {
                var reason = response?.ReplyMessage;
                var phone = response?.Phone;
                _logger.Warning("Second factor verification for user '{user:l}' from {host:l}:{port} failed with reason='{reason:l}'. User phone {phone:l}", userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, reason, phone);
            }

            return responseCode;
        }

        public async Task<PacketCode> Challenge(PendingRequest request, ClientConfiguration clientConfig, string userName, string answer, string state)
        {
            var url = _serviceConfiguration.ApiUrl + "/access/requests/ra/challenge";
            var payload = new
            {
                Identity = userName,
                Challenge = answer,
                RequestId = state
            };

            var response = await SendRequest(url, payload, clientConfig);
            var responseCode = ConvertToRadiusCode(response);

            request.ReplyMessage = response.ReplyMessage;

            if (responseCode == PacketCode.AccessAccept && !response.Bypassed)
            {
                _logger.Information("Second factor for user '{user:l}' verified successfully. Authenticator '{authenticator:l}', account '{account:l}'", userName, response?.Authenticator, response?.Account);
            }

            return responseCode;
        }

        private async Task<MultiFactorAccessRequest> SendRequest(string url, object payload, ClientConfiguration clientConfiguration)
        {
            try
            {
                //make sure we can communicate securely
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                ServicePointManager.DefaultConnectionLimit = 100;

                var json = JsonConvert.SerializeObject(payload);

                _logger.Debug("Sending request to API: {@payload}", payload);

                var requestData = Encoding.UTF8.GetBytes(json);
                byte[] responseData = null;

                //basic authorization
                var auth = Convert.ToBase64String(Encoding.ASCII.GetBytes(clientConfiguration.MultifactorApiKey + ":" + clientConfiguration.MultiFactorApiSecret));

                using (var web = new WebClient())
                {
                    web.Headers.Add("Content-Type", "application/json");
                    web.Headers.Add("Authorization", "Basic " + auth);

                    if (!string.IsNullOrEmpty(_serviceConfiguration.ApiProxy))
                    {
                        _logger.Debug("Using proxy " + _serviceConfiguration.ApiProxy);
                        var proxyUri = new Uri(_serviceConfiguration.ApiProxy);
                        web.Proxy = new WebProxy(proxyUri);

                        if (!string.IsNullOrEmpty(proxyUri.UserInfo))
                        {
                            var credentials = proxyUri.UserInfo.Split(new[] { ':' }, 2);
                            web.Proxy.Credentials = new NetworkCredential(credentials[0], credentials[1]);
                        }
                    }

                    responseData = await web.UploadDataTaskAsync(url, "POST", requestData);
                }

                json = Encoding.UTF8.GetString(responseData);
                var response = JsonConvert.DeserializeObject<MultiFactorApiResponse<MultiFactorAccessRequest>>(json);

                _logger.Debug("Received response from API: {@response}", response);

                if (!response.Success)
                {
                    _logger.Warning("Got unsuccessful response from API: {@response}", response);
                }

                return response.Model;
            }
            catch (Exception ex)
            {
                _logger.Error($"Multifactor API host unreachable: {url}\r\n{ex.Message}");

                if (clientConfiguration.BypassSecondFactorWhenApiUnreachable)
                {
                    _logger.Warning("Bypass second factor");
                    return MultiFactorAccessRequest.Bypass;
                }

                return null;
            }
        }

        private PacketCode ConvertToRadiusCode(MultiFactorAccessRequest multifactorAccessRequest)
        {
            if (multifactorAccessRequest == null)
            {
                return PacketCode.AccessReject;
            }
            
            switch (multifactorAccessRequest.Status)
            {
                case "Granted":     //authenticated by push
                    return PacketCode.AccessAccept;
                case "Denied":
                    return PacketCode.AccessReject; //access denied
                case "AwaitingAuthentication":
                    return PacketCode.AccessChallenge;  //otp code required
                default:
                    _logger.Warning($"Got unexpected status from API: {multifactorAccessRequest.Status}");
                    return PacketCode.AccessReject; //access denied
            }
        }

        private bool TryHitCache(string remoteHost, string userName, ClientConfiguration clientConfiguration)
        {
            if (string.IsNullOrEmpty(remoteHost))
            {
                _logger.Warning($"Remote host parameter miss for user {userName}");
                return false;
            }

            var id = AuthenticatedClient.CreateId(remoteHost, userName);
            if (_authenticatedClients.TryGetValue(id, out var authenticatedClient))
            {
                _logger.Debug($"User {userName} from {remoteHost} authenticated {authenticatedClient.Elapsed.ToString("hh\\:mm\\:ss")} ago. Bypass period: {clientConfiguration.BypassSecondFactorPeriod}m");

                if (authenticatedClient.Elapsed.TotalMinutes <= (clientConfiguration.BypassSecondFactorPeriod ?? 0))
                {
                    return true;
                }
                else
                {
                    _authenticatedClients.TryRemove(id, out _);
                }
            }

            return false;
        }

        private void SetCache(string remoteHost, string userName)
        {
            if (string.IsNullOrEmpty(remoteHost))
            {
                return; 
            }
            
            var client = new AuthenticatedClient
            {
                RemoteHost = remoteHost,
                UserName = userName,
                AuthenticatedAt = DateTime.Now
            };

            if (!_authenticatedClients.ContainsKey(client.Id))
            {
                _authenticatedClients.TryAdd(client.Id, client);
            }
        }

        private string GetPassCodeOrNull(string userPassword, ClientConfiguration clientConfiguration)
        {
            //only if first authentication factor is None, assuming that Password contains OTP code
            if (clientConfiguration.FirstFactorAuthenticationSource != AuthenticationSource.None)
            {
                return null;
            }
            
            /* valid passcodes:
             *  6 digits: otp
             *  t: Telegram
             *  m: MobileApp
             *  s: SMS
             *  c: PhoneCall
             */

            if (string.IsNullOrEmpty(userPassword))
            {
                return null;
            }

            var isOtp = Regex.IsMatch(userPassword.Trim(), "^[0-9]{1,6}$");
            if (isOtp)
            {
                return userPassword.Trim();
            }

            if (new [] {"t", "m", "s", "c"}.Any( c => c == userPassword.Trim().ToLower()))
            {
                return userPassword.Trim().ToLower();
            }

            //not a passcode
            return null;
        }
    }

    public class MultiFactorApiResponse<TModel>
    {
        public bool Success { get; set; }

        public TModel Model { get; set; }
    }

    public class MultiFactorAccessRequest
    {
        public string Id { get; set; }
        public string Identity { get; set; }
        public string Phone { get; set; }
        public string Status { get; set; }
        public string ReplyMessage { get; set; }
        public bool Bypassed { get; set; }
        public string Authenticator { get; set; }
        public string Account { get; set; }

        public static MultiFactorAccessRequest Bypass
        {
            get
            {
                return new MultiFactorAccessRequest { Status = "Granted", Bypassed = true };
            }
        } 
    }
}
