using MultiFactor.Radius.Adapter.Server;
using Serilog.Core;
using Serilog.Events;
using System;

namespace MultiFactor.Radius.Adapter.Logging.Enrichers
{
    internal class RadiusPacketLogEventEnricher : ILogEventEnricher
    {
        private const string _callingStationIdToken = "CallingStationId";

        private readonly RequestScope _requestScope;

        private RadiusPacketLogEventEnricher(RequestScope requestScope)
        {
            _requestScope = requestScope;
        }

        public static RadiusPacketLogEventEnricher Create(RequestScope requestScope)
        {
            if (requestScope is null) throw new ArgumentNullException(nameof(requestScope));
            return new RadiusPacketLogEventEnricher(requestScope);
        }

        public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
        {
            var property = propertyFactory.CreateProperty(_callingStationIdToken, _requestScope.Packet.CallingStationId);
            logEvent.AddOrUpdateProperty(property);
        }
    }
}
