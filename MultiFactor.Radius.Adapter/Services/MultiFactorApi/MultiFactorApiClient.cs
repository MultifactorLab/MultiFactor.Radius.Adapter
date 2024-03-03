//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md


using MultiFactor.Radius.Adapter.Configuration;
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
        private readonly ServiceConfiguration _serviceConfiguration;
        private readonly AuthenticatedClientCache _authenticatedClientCache;
        private readonly IHttpClientFactory _httpClientFactory;
        readonly JsonSerializerOptions _serialazerOptions;
        private readonly ILogger _logger;

        public MultifactorApiClient(ServiceConfiguration serviceConfiguration, 
            AuthenticatedClientCache authenticatedClientCache, 
            IHttpClientFactory httpClientFactory, 
            ILogger logger)
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

        public Task<AccessRequestDto> CreateRequestAsync(CreateRequestDto dto, ClientConfiguration configuration)
        {
            if (dto is null)
            {
                throw new ArgumentNullException(nameof(dto));
            }

            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var url = $"{_serviceConfiguration.ApiUrl}/access/requests/ra";
            return SendRequest(url, dto, configuration);
        }

        public Task<AccessRequestDto> ChallengeAsync(ChallengeDto dto, ClientConfiguration configuration)
        {
            if (dto is null)
            {
                throw new ArgumentNullException(nameof(dto));
            }

            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var url = $"{_serviceConfiguration.ApiUrl}/access/requests/ra/challenge";
            return SendRequest(url, dto, configuration);
        }

        private async Task<AccessRequestDto> SendRequest(string url, object payload, ClientConfiguration clientConfiguration)
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

                //basic authorization
                var auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientConfiguration.MultifactorApiKey}:{clientConfiguration.MultiFactorApiSecret}"));
                message.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

                var httpClient = _httpClientFactory.CreateClient(nameof(MultifactorApiClient));
                var res = await httpClient.SendAsync(message);
                res.EnsureSuccessStatusCode();

                var jsonResponse = await res.Content.ReadAsStringAsync();
                var response = JsonSerializer.Deserialize<MultiFactorApiResponse<AccessRequestDto>>(jsonResponse, _serialazerOptions);

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
    }
}
