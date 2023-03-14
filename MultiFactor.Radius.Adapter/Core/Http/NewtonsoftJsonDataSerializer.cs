using System;
using System.Net.Http;
using System.Threading.Tasks;
using Serilog;
using Newtonsoft.Json;
using System.Text;

namespace MultiFactor.Radius.Adapter.Core.Http
{
    public class NewtonsoftJsonDataSerializer : IJsonDataSerializer
    {
        private readonly ILogger _logger;

        public NewtonsoftJsonDataSerializer(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<T> DeserializeAsync<T>(HttpContent content)
        {
            var jsonResponse = await content.ReadAsStringAsync();
            var parsed = JsonConvert.DeserializeObject<T>(jsonResponse);
            _logger.Debug("Received response from API: {@response}", parsed);
            return parsed;
        }

        public StringContent Serialize(object data)
        {
            _logger.Debug("Sending request to API: {@payload}", data);
            var payload = JsonConvert.SerializeObject(data);
            return new StringContent(payload, Encoding.UTF8, "application/json");
        }
    }
}
