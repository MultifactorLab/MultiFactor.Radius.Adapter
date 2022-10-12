using Serilog;
using System;
using System.Diagnostics;
using System.DirectoryServices.Protocols;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class LdapConnectionAdapter : IDisposable
    {
        private readonly LdapConnection _connection;
        private readonly ILogger _logger;

        public LdapConnectionAdapter(LdapConnection connection, ILogger logger)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public SearchResponse Query(string baseDn, string filter, SearchScope scope, bool chaseRefs, params string[] attributes)
        {
            var searchRequest = new SearchRequest
                (baseDn,
                 filter,
                 scope,
                 attributes);

            if (chaseRefs)
            {
                _connection.SessionOptions.ReferralChasing = ReferralChasingOptions.All;
            }
            else
            {
                _connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            }

            var sw = Stopwatch.StartNew();

            var response = (SearchResponse)_connection.SendRequest(searchRequest);

            if (sw.Elapsed.TotalSeconds > 2)
            {
                _logger.Warning($"Slow response while querying {baseDn}. Elapsed {sw.Elapsed}");
            }

            return response;
        }

        public void Dispose()
        {
            _connection?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
