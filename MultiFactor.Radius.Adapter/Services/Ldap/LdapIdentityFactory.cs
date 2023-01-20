using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using System;
using System.DirectoryServices.AccountManagement;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public static class LdapIdentityFactory
    {
        public static LdapIdentity CreateUserIdentity(ClientConfiguration clientConfig, string userName)
        {
            if (string.IsNullOrEmpty(userName)) throw new ArgumentNullException(nameof(userName));

            var user = LdapIdentity.ParseUser(userName);
            if (user.Type == IdentityType.UserPrincipalName)
            {
                var suffix = user.UpnToSuffix();
                if (!clientConfig.IsPermittedDomain(suffix))
                {
                    throw new UserDomainNotPermittedException($"User domain {suffix} not permitted");
                }
            }
            else
            {
                if (clientConfig.RequiresUpn)
                {
                    throw new UserNameFormatException("Only UserPrincipalName format permitted, see configuration");
                }
            }

            return user;
        }
    }
}
