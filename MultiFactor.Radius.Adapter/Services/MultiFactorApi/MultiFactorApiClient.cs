//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Services.MultiFactorApi.Dto;
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
    public class MultifactorApiClient
    {
        private readonly IHttpClientFactory _httpClientFactory;
        readonly JsonSerializerOptions _serialazerOptions;
        private readonly ILogger _logger;

        public MultifactorApiClient(IHttpClientFactory httpClientFactory, ILogger logger)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _serialazerOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

        public Task<AccessRequestDto> CreateRequestAsync(string apiUrl, CreateRequestDto dto, ApiAuthHeaderValue authHeaderValue)
        {
            if (string.IsNullOrWhiteSpace(apiUrl))
            {
                throw new ArgumentException($"'{nameof(apiUrl)}' cannot be null or whitespace.", nameof(apiUrl));
            }

            if (dto is null)
            {
                throw new ArgumentNullException(nameof(dto));
            }

            if (authHeaderValue is null)
            {
                throw new ArgumentNullException(nameof(authHeaderValue));
            }

            var url = $"{apiUrl}/access/requests/ra";
            return SendRequest(url, dto, authHeaderValue);
        }

        public Task<AccessRequestDto> ChallengeAsync(string apiUrl, ChallengeDto dto, ApiAuthHeaderValue authHeaderValue)
        {
            if (string.IsNullOrWhiteSpace(apiUrl))
            {
                throw new ArgumentException($"'{nameof(apiUrl)}' cannot be null or whitespace.", nameof(apiUrl));
            }

            if (dto is null)
            {
                throw new ArgumentNullException(nameof(dto));
            }

            if (authHeaderValue is null)
            {
                throw new ArgumentNullException(nameof(authHeaderValue));
            }

            var url = $"{apiUrl}/access/requests/ra/challenge";
            return SendRequest(url, dto, authHeaderValue);
        }

        private async Task<AccessRequestDto> SendRequest(string url, object payload, ApiAuthHeaderValue authHeaderValue)
        {
            try
            {
                //make sure we can communicate securely
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                ServicePointManager.DefaultConnectionLimit = 100;

                var json = JsonSerializer.Serialize(payload, _serialazerOptions);

                _logger.Debug("Sending request to API: {@payload}", payload);

                StringContent jsonContent = new StringContent(json, Encoding.UTF8, "application/json");
                HttpRequestMessage message = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = jsonContent
                };

                message.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", authHeaderValue.Value);

                var httpClient = _httpClientFactory.CreateClient(nameof(MultifactorApiClient));
                var res = await httpClient.SendAsync(message);
                if ((int)res.StatusCode == 429)
                {
                    _logger.Warning("Got unsuccessful api response: {reason}", res.ReasonPhrase);
                    return new AccessRequestDto() { Status = Literals.RadiusCode.Denied, ReplyMessage = "Too many requests"};
                }

                res.EnsureSuccessStatusCode();

                var jsonResponse = await res.Content.ReadAsStringAsync();
                var response = JsonSerializer.Deserialize<MultiFactorApiResponse<AccessRequestDto>>(jsonResponse, _serialazerOptions);

                _logger.Debug("Received response from API: {@response}", response);

                if (!response.Success)
                {
                    _logger.Warning("Got unsuccessful api response with code {StatusCode} ({StatusCodeText}) from API {Url}: {@response}", (int)res.StatusCode, res.StatusCode, url, response);
                }

                return response.Model;
            }
            catch (TaskCanceledException)
            {
                var message = "Multifactor API timeout expired.";
                _logger.Warning(message);
                return new AccessRequestDto() { Status = Literals.RadiusCode.Denied, ReplyMessage = message };
            }
            catch (Exception ex)
            {
                throw new MultifactorApiUnreachableException($"Multifactor API host unreachable: {url}. Reason: {ex.Message}", ex);
            }
        }
    }
}
