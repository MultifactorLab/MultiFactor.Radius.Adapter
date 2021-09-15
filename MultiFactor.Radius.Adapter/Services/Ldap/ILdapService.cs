using MultiFactor.Radius.Adapter.Server;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public interface ILdapService
    {
        bool VerifyCredentialAndMembership(string userName, string password, PendingRequest request);
    }
}
