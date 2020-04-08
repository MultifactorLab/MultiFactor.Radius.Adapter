using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace MultiFactor.Radius.Adapter
{
    /// <summary>
    /// Service to interact with multifactor web api
    /// </summary>
    public class MultiFactorApiClient
    {
        private Configuration _configuration;
        private ILogger _logger;

        public MultiFactorApiClient(Configuration configuration, ILogger logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public PacketCode CreateSecondFactorRequest(string userName, out string state)
        {
            var url = _configuration.ApiUrl + "/access/requests/ra";
            var payload = new
            {
                Identity = userName,
            };

            var response = SendRequest(url, payload, out var requestId);
            state = requestId;

            return response;
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

            var response = SendRequest(url, payload, out var requestId);

            return response;
        }

        private PacketCode SendRequest(string url, object payload, out string requestId)
        {
            requestId = null;

            try
            {
                //make sure we can communicate securely
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

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
                    return PacketCode.AccessReject; //access denied
                }

                switch (response.Model.Status)
                {
                    case "Granted":     //authenticated by push
                        return PacketCode.AccessAccept;
                    case "Denied":
                        return PacketCode.AccessReject; //access denied
                    case "AwaitingAuthentication":
                        requestId = response.Model.Id;
                        return PacketCode.AccessChallenge;  //otp code required
                    default:
                        _logger.Warning($"Got unexpected status from API: {response.Model.Status}");
                        return PacketCode.AccessReject; //access denied
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Multifactor API host unreachable: {url}");
                return PacketCode.AccessReject; //access denied
            }
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
    }

}
