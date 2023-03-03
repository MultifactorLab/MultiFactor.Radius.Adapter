//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md


using MultiFactor.Radius.Adapter.Configuration;
using Serilog;
using System;
using System.Net;
using System.Text;

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi
{
    public class CustomWebClient : WebClient
    {
        private readonly TimeSpan? _timeout;

        public CustomWebClient(TimeSpan? timeout)
        {
            _timeout = timeout;
        }

        protected override WebRequest GetWebRequest(Uri uri)
        {
            var request = base.GetWebRequest(uri);
            if (_timeout != null)
            {
                request.Timeout = (int)_timeout.Value.TotalMilliseconds;
            }
            return request;
        }
    }

    public class WebClientFactory
    {
        private readonly ServiceConfiguration _serviceConfig;
        private readonly ILogger _logger;

        public WebClientFactory(ServiceConfiguration serviceConfig, ILogger logger)
        {
            _serviceConfig = serviceConfig ?? throw new ArgumentNullException(nameof(serviceConfig));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public WebClient Create(ClientConfiguration clientConfig)
        {
            if (clientConfig is null) throw new ArgumentNullException(nameof(clientConfig));

            var web = new CustomWebClient(_serviceConfig.ApiTimeout);
            
            web.Headers.Add("Content-Type", "application/json");
            web.Headers.Add("Authorization", $"Basic {BuildBasicAuth(clientConfig)}");

            if (!string.IsNullOrEmpty(_serviceConfig.ApiProxy))
            {
                _logger.Debug("Using proxy {addr:l}", _serviceConfig.ApiProxy);

                var proxyUri = new Uri(_serviceConfig.ApiProxy);
                web.Proxy = new WebProxy(proxyUri);

                if (!string.IsNullOrEmpty(proxyUri.UserInfo))
                {
                    var credentials = proxyUri.UserInfo.Split(new[] { ':' }, 2);
                    web.Proxy.Credentials = new NetworkCredential(credentials[0], credentials[1]);
                }
            }

            return web;
        }

        private static string BuildBasicAuth(ClientConfiguration clientConfig)
        {
            var bytes = Encoding.ASCII.GetBytes($"{clientConfig.MultifactorApiKey}:{clientConfig.MultiFactorApiSecret}");
            return Convert.ToBase64String(bytes);
        }
    }
}
