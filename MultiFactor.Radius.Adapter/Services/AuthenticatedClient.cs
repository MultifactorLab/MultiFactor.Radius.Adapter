//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;
namespace MultiFactor.Radius.Adapter.Services
{
    /// <summary>
    /// Authenticated client
    /// </summary>
    public class AuthenticatedClient
    {
        public string Id => CreateId(RemoteHost, UserName);
        
        public string RemoteHost { get; set; }
        public string UserName { get; set; }
        public DateTime AuthenticatedAt { get; set; }

        public TimeSpan Elapsed => DateTime.Now - AuthenticatedAt;

        public static string CreateId(string host, string user)
        {
            return $"{host}:{user}";
        }
    }
}
