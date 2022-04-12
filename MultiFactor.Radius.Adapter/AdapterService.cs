using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using Serilog;
using System;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter
{
    public partial class AdapterService : ServiceBase
    {
        private RadiusServer _radiusServer;

        public AdapterService(ServiceConfiguration configuration, IRadiusDictionary dictionary, ILogger logger)
        {
            var packetParser = new RadiusPacketParser(logger, dictionary);
            _radiusServer = new RadiusServer(configuration, dictionary, packetParser, logger);

            InitializeComponent();
        }

        public void StartServer()
        {
            _radiusServer.Start();
        }

        public void StopServer()
        {
            _radiusServer.Stop();
            //2 sec delay to flush logs
            Task.WaitAny(Task.Delay(TimeSpan.FromSeconds(2)));
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
