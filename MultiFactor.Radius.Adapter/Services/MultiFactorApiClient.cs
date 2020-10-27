//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md


using MultiFactor.Radius.Adapter.Core;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace MultiFactor.Radius.Adapter.Services
{
    /// <summary>
    /// Service to interact with multifactor web api
    /// </summary>
    public class MultiFactorApiClient
    {
        private Configuration _configuration;
        private ILogger _logger;

        private static readonly ConcurrentDictionary<string, AuthenticatedClient> _authenticatedClients = new ConcurrentDictionary<string, AuthenticatedClient>();

        public MultiFactorApiClient(Configuration configuration, ILogger logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public PacketCode CreateSecondFactorRequest(string remoteHost, string userName, string userPassword, string email, string userPhone, out string state)
        {
            state = null;
            
            //try to get authenticated client to bypass second factor if configured
            if (_configuration.BypassSecondFactorPeriod > 0)
            {
                if (TryHitCache(remoteHost, userName))
                {
                    _logger.Information($"Bypass second factor for user {userName} from {remoteHost}");
                    return PacketCode.AccessAccept;
                }
            }
            
            var url = _configuration.ApiUrl + "/access/requests/ra";
            var payload = new
            {
                Identity = userName,
                Email = email,
                Phone = userPhone,
                PassCode = GetPassCodeOrNull(userPassword)
            };

            var response = SendRequest(url, payload);
            var responseCode = ConvertToRadiusCode(response);

            state = response?.Id;

            if (responseCode == PacketCode.AccessAccept && !response.Bypassed)
            {
                _logger.Information($"Second factor for user '{userName}' verifyed successfully");

                if (_configuration.BypassSecondFactorPeriod > 0)
                {
                    SetCache(remoteHost, userName);
                }
            }

            return responseCode;
        }

        public PacketCode VerifyOtpCode(string userName, string otpCode, string state)
        {
            var url = _configuration.ApiUrl + "/access/requests/ra/challenge";
            var payload = new
            {
                Identity = userName,
                Challenge = otpCode,
                RequestId = state
            };

            var response = SendRequest(url, payload);
            var responseCode = ConvertToRadiusCode(response);

            if (responseCode == PacketCode.AccessAccept && !response.Bypassed)
            {
                _logger.Information($"Second factor for user '{userName}' verifyed successfully");
            }

            return responseCode;
        }

        private MultiFactorAccessRequest SendRequest(string url, object payload)
        {
            try
            {
                //make sure we can communicate securely
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                ServicePointManager.DefaultConnectionLimit = 100;

                var json = JsonConvert.SerializeObject(payload);

                _logger.Debug($"Sending request to API: {json}");

                var requestData = Encoding.UTF8.GetBytes(json);
                byte[] responseData = null;

                //basic authorization
                var auth = Convert.ToBase64String(Encoding.ASCII.GetBytes(_configuration.NasIdentifier + ":" + _configuration.MultiFactorSharedSecret));

                using (var web = new WebClient())
                {
                    web.Headers.Add("Content-Type", "application/json");
                    web.Headers.Add("Authorization", "Basic " + auth);
                    responseData = web.UploadData(url, "POST", requestData);
                }

                json = Encoding.UTF8.GetString(responseData);

                _logger.Debug($"Received response from API: {json}");

                var response = JsonConvert.DeserializeObject<MultiFactorApiResponse<MultiFactorAccessRequest>>(json);

                if (!response.Success)
                {
                    _logger.Warning($"Got unsuccessful response from API: {json}");
                }

                return response.Model;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Multifactor API host unreachable: {url}");

                if (_configuration.BypassSecondFactorWhenApiUnreachable)
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

        private bool TryHitCache(string remoteHost, string userName)
        {
            if (string.IsNullOrEmpty(remoteHost))
            {
                _logger.Warning($"Remote host parameter miss for user {userName}");
                return false;
            }

            var id = AuthenticatedClient.CreateId(remoteHost, userName);
            if (_authenticatedClients.TryGetValue(id, out var authenticatedClient))
            {
                _logger.Debug($"User {userName} from {remoteHost} authenticated {authenticatedClient.Elapsed.ToString("hh\\:mm\\:ss")} ago. Bypass period: {_configuration.BypassSecondFactorPeriod}m");

                if (authenticatedClient.Elapsed.TotalMinutes <= (_configuration.BypassSecondFactorPeriod ?? 0))
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

        private string GetPassCodeOrNull(string userPassword)
        {
            //only if first authentication factor is None, assuming that Password contains OTP code
            if (_configuration.FirstFactorAuthenticationSource != AuthenticationSource.None)
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
        public string Status { get; set; }

        public bool Bypassed { get; set; }

        public static MultiFactorAccessRequest Bypass
        {
            get
            {
                return new MultiFactorAccessRequest { Status = "Granted", Bypassed = true };
            }
        } 
    }
}
