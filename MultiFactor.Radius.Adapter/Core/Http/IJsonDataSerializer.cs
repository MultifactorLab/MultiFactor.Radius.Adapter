using System.Net.Http;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Core.Http
{
    public interface IJsonDataSerializer
    {
        StringContent Serialize(object data);
        Task<T> DeserializeAsync<T>(HttpContent content);
    }
}
