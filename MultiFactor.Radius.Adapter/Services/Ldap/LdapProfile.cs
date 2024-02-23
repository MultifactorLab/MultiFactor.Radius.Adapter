using MultiFactor.Radius.Adapter.Configuration;
using System;
using System.Collections.ObjectModel;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class LdapProfile
    {
        private readonly ClientConfiguration _configuration;

        public LdapIdentity BaseDn { get; }
        public string DistinguishedName => LdapAttrs.GetValue("distinguishedname");
        public string Upn => LdapAttrs.GetValue("userprincipalname");
        public string DisplayName => LdapAttrs.GetValue("displayname");
        public string Email => LdapAttrs.GetValue("mail");

        private string _phone = string.Empty;
        public string Phone
        {
            get
            {
                if (_phone != string.Empty)
                {
                    return _phone;
                }

                if (_configuration.PhoneAttributes.Count == 0)
                {
                    _phone = LdapAttrs.GetValue("phone");
                    return _phone;
                }

                _phone = _configuration.PhoneAttributes
                    .Select(x => LdapAttrs.GetValue(x))
                    .FirstOrDefault(x => x != null) ?? LdapAttrs.GetValue("phone");

                return _phone;
            }
        }

        public ReadOnlyCollection<string> MemberOf => LdapAttrs.GetValues("memberOf");

        public ILdapAttributes LdapAttrs { get; private set; }

        private LdapProfile(ClientConfiguration configuration)
        {
            BaseDn = null;
            LdapAttrs = new LdapAttributes();
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public LdapProfile(LdapIdentity baseDn, ILdapAttributes attributes, ClientConfiguration configuration)
        {
            BaseDn = baseDn ?? throw new ArgumentNullException(nameof(baseDn));
            LdapAttrs = attributes ?? throw new ArgumentNullException(nameof(attributes));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public static LdapProfile Empty(ClientConfiguration configuration) => new LdapProfile(configuration);   
        
        public void UpdateAttributes(ILdapAttributes attributes)
        {
            LdapAttrs = attributes ?? throw new ArgumentNullException(nameof(attributes));
        }
    }
}