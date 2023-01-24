//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class LdapDomainEqualityComparer : IEqualityComparer<LdapIdentity>
    {
        public bool Equals(LdapIdentity x, LdapIdentity y)
        {
            if (x == null || y == null) return false;
            return x == y || x.Name == y.Name;
        }

        public int GetHashCode(LdapIdentity obj)
        {
            return obj.GetHashCode();
        }
    }
}