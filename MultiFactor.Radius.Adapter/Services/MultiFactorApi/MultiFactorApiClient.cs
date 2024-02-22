//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md


using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Configuration.Features.PreAuthnModeFeature;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using Serilog;
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi
{
    /// <summary>
    /// Service to interact with multifactor web api
    /// </summary>
    public class MultiFactorApiClient
    {
        private readonly ServiceConfiguration _serviceConfiguration;
        private readonly AuthenticatedClientCache _authenticatedClientCache;
        private readonly IHttpClientFactory _httpClientFactory;
        readonly JsonSerializerOptions _serialazerOptions;
        private readonly ILogger _logger;

        public MultiFactorApiClient(ServiceConfiguration serviceConfiguration, AuthenticatedClientCache authenticatedClientCache, IHttpClientFactory httpClientFactory, ILogger logger)
        {
            _serviceConfiguration = serviceConfiguration ?? throw new ArgumentNullException(nameof(serviceConfiguration));
            _authenticatedClientCache = authenticatedClientCache ?? throw new ArgumentNullException(nameof(authenticatedClientCache));
            _httpClientFactory = httpClientFactory;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _serialazerOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

        public async Task<PacketCode> CreateSecondFactorRequest(PendingRequest request)
        {
            var userName = request.GetSecondFactorIdentity(request.Configuration);
            var displayName = request.DisplayName;
            var email = request.EmailAddress;
            var userPhone = request.UserPhone;
            var callingStationId = request.RequestPacket.CallingStationId;

            string calledStationId = null;

            if (request.RequestPacket.IsWinLogon) //only for winlogon yet
            {
                calledStationId = request.RequestPacket.CalledStationId;
            }

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Empty user name for second factor request. Request rejected.");
                return PacketCode.AccessReject;
            }

            //remove user information for privacy
            switch (request.Configuration.PrivacyMode.Mode)
            {
                case PrivacyMode.Full:
                    displayName = null;
                    email = null;
                    userPhone = null;
                    callingStationId = "";
                    calledStationId = null;
                    break;

                case PrivacyMode.Partial:
                    if (!request.Configuration.PrivacyMode.HasField("Name"))
                    {
                        displayName = null;
                    }

                    if (!request.Configuration.PrivacyMode.HasField("Email"))
                    {
                        email = null;
                    }

                    if (!request.Configuration.PrivacyMode.HasField("Phone"))
                    {
                        userPhone = null;
                    }

                    if (!request.Configuration.PrivacyMode.HasField("RemoteHost"))
                    {
                        callingStationId = "";
                    }

                    calledStationId = null;

                    break;
            }

            //try to get authenticated client to bypass second factor if configured
            if (_authenticatedClientCache.TryHitCache(request.RequestPacket.CallingStationId, userName, request.Configuration))
            {
                _logger.Information("Bypass second factor for user '{name:l}' with identity attribyte '{user:l}' from {host:l}:{port}", request.UserName, userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessAccept;
            }

            var url = _serviceConfiguration.ApiUrl + "/access/requests/ra";
            var payload = new
            {
                Identity = userName,
                Name = displayName,
                Email = email,
                Phone = userPhone,
                PassCode = GetPassCodeOrNull(request),
                CallingStationId = callingStationId,
                CalledStationId = calledStationId,
                Capabilities = new
                {
                    InlineEnroll = true
                },
                GroupPolicyPreset = new
                {
                    request.Configuration.SignUpGroups
                }
            };

            try
            {
                var response = await SendRequest(url, payload, request.Configuration);
                var responseCode = ConvertToRadiusCode(response);

                request.State = response?.Id;
                request.ReplyMessage = response?.ReplyMessage;

                if (responseCode == PacketCode.AccessAccept && !response.Bypassed)
                {
                    LogGrantedInfo(userName, response, request);
                    _authenticatedClientCache.SetCache(request.RequestPacket.CallingStationId, userName, request.Configuration);
                }

                if (responseCode == PacketCode.AccessReject)
                {
                    _logger.Warning("Second factor verification for user '{name:l}' with identity attribyte '{user:l}' from {host:l}:{port} failed with reason='{reason:l}'. User phone {phone:l}",
                        request.UserName, userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, response?.ReplyMessage, response?.Phone);
                }

                return responseCode;
            }
            catch (Exception ex)
            {
                return HandleException(ex, userName, request);
            }
        }

        public async Task<PacketCode> Challenge(PendingRequest request, string answer, string state)
        {
            var url = _serviceConfiguration.ApiUrl + "/access/requests/ra/challenge";
            var userName = request.GetSecondFactorIdentity(request.Configuration);
            var payload = new
            {
                Identity = userName,
                Challenge = answer,
                RequestId = state
            };

            try
            {
                var response = await SendRequest(url, payload, request.Configuration);
                var responseCode = ConvertToRadiusCode(response);

                request.ReplyMessage = response.ReplyMessage;

                if (responseCode == PacketCode.AccessAccept && !response.Bypassed)
                {
                    LogGrantedInfo(userName, response, request);
                    _authenticatedClientCache.SetCache(request.RequestPacket.CallingStationId, userName, request.Configuration);
                }

                return responseCode;
            }
            catch (Exception ex)
            {
                return HandleException(ex, userName, request);
            }
        }

        private async Task<MultiFactorAccessRequest> SendRequest(string url, object payload, ClientConfiguration clientConfiguration)
        {
            try
            {
                //make sure we can communicate securely
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                ServicePointManager.DefaultConnectionLimit = 100;

                var json = JsonSerializer.Serialize(payload, _serialazerOptions);

                _logger.Debug("Sending request to API: {@payload}", payload);

                //basic authorization
                var auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientConfiguration.MultifactorApiKey}:{clientConfiguration.MultiFactorApiSecret}"));
                var httpClient = _httpClientFactory.CreateClient(nameof(MultiFactorApiClient));

                StringContent jsonContent = new StringContent(json, Encoding.UTF8, "application/json");
                HttpRequestMessage message = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = jsonContent
                };
                message.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);
                var res = await httpClient.SendAsync(message);
                res.EnsureSuccessStatusCode();
                var jsonResponse = await res.Content.ReadAsStringAsync();
                var response = JsonSerializer.Deserialize<MultiFactorApiResponse<MultiFactorAccessRequest>>(jsonResponse, _serialazerOptions);

                _logger.Debug("Received response from API: {@response}", response);

                if (!response.Success)
                {
                    _logger.Warning("Got unsuccessful response with code {StatusCode} ({StatusCodeText}) from API {Url}: {@response}", (int)res.StatusCode, res.StatusCode, url, response);
                }

                return response.Model;
            }
            catch (TaskCanceledException tce)
            {
                throw new MultifactorApiUnreachableException($"Multifactor API host unreachable: {url}. Reason: Timeout", tce);
            }
            catch (Exception ex)
            {
                throw new MultifactorApiUnreachableException($"Multifactor API host unreachable: {url}. Reason: {ex.Message}", ex);
            }
        }

        private PacketCode HandleException(Exception ex, string username, PendingRequest request)
        {
            if (ex is MultifactorApiUnreachableException apiEx)
            {
                _logger.Error("Error occured while requesting API for user '{user:l}' from {host:l}:{port}, {msg:l}",
                    username,
                    request.RemoteEndpoint.Address,
                    request.RemoteEndpoint.Port,
                    apiEx.Message);

                if (request.Configuration.BypassSecondFactorWhenApiUnreachable)
                {
                    _logger.Warning("Bypass second factor for user '{user:l}' from {host:l}:{port}",
                        username,
                        request.RemoteEndpoint.Address,
                        request.RemoteEndpoint.Port);
                    return ConvertToRadiusCode(MultiFactorAccessRequest.Bypass);
                }
            }

            return ConvertToRadiusCode(null);
        }

        private PacketCode ConvertToRadiusCode(MultiFactorAccessRequest multifactorAccessRequest)
        {
            if (multifactorAccessRequest == null)
            {
                return PacketCode.AccessReject;
            }

            switch (multifactorAccessRequest.Status)
            {
                case Literals.RadiusCode.Granted:     //authenticated by push
                    return PacketCode.AccessAccept;
                case Literals.RadiusCode.Denied:
                    return PacketCode.AccessReject; //access denied
                case Literals.RadiusCode.AwaitingAuthentication:
                    return PacketCode.AccessChallenge;  //otp code required
                default:
                    _logger.Warning($"Got unexpected status from API: {multifactorAccessRequest.Status}");
                    return PacketCode.AccessReject; //access denied
            }
        }

        private string GetPassCodeOrNull(PendingRequest request)
        {
            //check static challenge
            var challenge = request.RequestPacket.TryGetChallenge();
            if (challenge != null)
            {
                return challenge;
            }

            //check password challenge (otp or passcode)
            var passphrase = request.Passphrase;

            if (request.Configuration.FirstFactorAuthenticationSource != AuthenticationSource.None && request.Configuration.PreAuthnMode.Mode == PreAuthnMode.None)
            {
                return null;
            }

            if (passphrase.IsEmpty)
            {
                return null;
            }

            return passphrase.Otp ?? passphrase.ProviderCode;
        }

        private void LogGrantedInfo(string userName, MultiFactorAccessRequest response, PendingRequest request)
        {
            string countryValue = null;
            string regionValue = null;
            string cityValue = null;
            string callingStationId = request?.RequestPacket?.CallingStationId;

            if (response != null && IPAddress.TryParse(callingStationId, out var ip))
            {
                countryValue = response.CountryCode;
                regionValue = response.Region;
                cityValue = response.City;
                callingStationId = ip.ToString();
            }

            _logger.Information("Second factor for user '{user:l}' verified successfully. Authenticator: '{authenticator:l}', account: '{account:l}', country: '{country:l}', region: '{region:l}', city: '{city:l}', calling-station-id: {clientIp}, authenticatorId: {authenticatorId}",
                        userName,
                        response?.Authenticator,
                        response?.Account,
                        countryValue,
                        regionValue,
                        cityValue,
                        callingStationId,
                        response.AuthenticatorId);
        }
    }
}
