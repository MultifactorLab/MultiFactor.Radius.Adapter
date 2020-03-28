using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using Serilog;
using System.ServiceProcess;

namespace MultiFactor.Radius.Adapter
{
    public partial class AdapterService : ServiceBase
    {
        private RadiusServer _radiusServer;

        public AdapterService(Configuration configuration, IRadiusDictionary dictionary, ILogger logger)
        {
            var packetParser = new RadiusPacketParser(logger, dictionary);
            _radiusServer = new RadiusServer(configuration, packetParser, logger);

            InitializeComponent();
        }

        public void StartServer()
        {
            _radiusServer.Start();
        }

        public void StopServer()
        {
            _radiusServer.Stop();
        }

        protected override void OnStart(string[] args)
        {
            StartServer();
        }

        protected override void OnStop()
        {
            StopServer();
        }
    }
}
