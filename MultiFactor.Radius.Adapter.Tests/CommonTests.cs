using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Tests.Fixtures;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace MultiFactor.Radius.Adapter.Tests
{
    public class CommonTests
    {
        [Fact]
        public async Task StatusServer_ShouldReturnServerInfo()
        {
            var server = TestRadiusAdapterServer.Create("127.0.0.1", 1812, config =>
            {
                config.RootConfigFilePath = AssetsAccess.GetAssetPath(TestAssetLocation.RootConfigs, "root-minimal-single.config");
            });
            server.Start();

            var cli = server.Service<ServiceConfiguration>().GetClient("nasid");

            var content = File.ReadAllText(AssetsAccess.GetAssetPath(TestAssetLocation.Packets, "status-server"));
            var bytes = PacketFactory.ParseHexString(content);
            var parser = server.Service<IRadiusPacketParser>();
            var packet = parser.Parse(bytes, new SharedSecret(cli.RadiusSharedSecret));
            var remote = new IPEndPoint(IPAddress.Parse("10.10.10.1"), 1812);
            var req = PendingRequest.Create(cli, remote, null, packet);

            var router = server.Service<RadiusRouter>();
            await router.HandleRequest(req);

            var sender = server.Service<TestRadiusResponseSender>();

            Assert.NotNull(sender.ResponsePacket);
            Assert.Equal(PacketCode.AccessAccept, sender.ResponsePacket.Id.Code);
            Assert.StartsWith("Server up", sender.ResponsePacket.GetAttribute<string>("Reply-Message"));
        }      
    }
}
