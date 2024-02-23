using System.Collections.ObjectModel;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public interface ILdapAttributes
    {
        ReadOnlyCollection<string> Keys { get; }
        bool Has(string attribute);
        string GetValue(string attribute);
        ReadOnlyCollection<string> GetValues(string attribute);
    }
}