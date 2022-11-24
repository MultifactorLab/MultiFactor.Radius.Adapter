//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;
namespace MultiFactor.Radius.Adapter.Services
{
    public class AuthenticatedClient
    {
        private readonly DateTime _authenticatedAt;

        public string Id { get; }
        public TimeSpan Elapsed => DateTime.Now - _authenticatedAt;

        public AuthenticatedClient(string id, DateTime authenticatedAt)
        {
            Id = id;
            _authenticatedAt = authenticatedAt;
        }

        public static AuthenticatedClient Create(string clientName, string callingStationId, string userName)
        {
            if (callingStationId is null) throw new ArgumentNullException(nameof(callingStationId));
            if (string.IsNullOrEmpty(userName)) throw new ArgumentException($"'{nameof(userName)}' cannot be null or empty.", nameof(userName));
            if (string.IsNullOrEmpty(clientName)) throw new ArgumentException($"'{nameof(clientName)}' cannot be null or empty.", nameof(clientName));

            return new AuthenticatedClient(ParseId(clientName, callingStationId, userName), DateTime.Now);
        }

        public static string ParseId(string callingStationId, string userName, string clientName)
        {
            return $"{clientName}-{callingStationId}-{userName}";
        }
    }
}
