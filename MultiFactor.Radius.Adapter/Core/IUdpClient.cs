using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Core
{
    public interface IUdpClient
    {
        Task<UdpReceiveResult> ReceiveAsync();
        int Send(byte[] dgram, int bytes, IPEndPoint endPoint);
        void Close();
    }
}
