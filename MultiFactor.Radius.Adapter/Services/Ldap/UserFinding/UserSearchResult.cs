//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;
using System.DirectoryServices.Protocols;

namespace MultiFactor.Radius.Adapter.Services.Ldap.UserFinding
{
    public class UserSearchResult
    {
        public SearchResultEntry Entry { get; }
        public LdapIdentity BaseDn { get; }

        public UserSearchResult(SearchResultEntry entry, LdapIdentity baseDn)
        {
            Entry = entry ?? throw new ArgumentNullException(nameof(entry));
            BaseDn = baseDn ?? throw new ArgumentNullException(nameof(baseDn));
        }
    }
}