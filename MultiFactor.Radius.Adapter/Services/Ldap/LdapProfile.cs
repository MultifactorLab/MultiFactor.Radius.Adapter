using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class LdapProfile
    {
        private readonly string[] _phoneAttrs;

        public LdapIdentity BaseDn { get; }
        public string DistinguishedName => LdapAttrs.GetValue("distinguishedname");
        public string Upn => LdapAttrs.GetValue("userprincipalname");
        public string DisplayName => LdapAttrs.GetValue("displayname");
        public string Email => LdapAttrs.GetValue("mail") ?? LdapAttrs.GetValue("email");

        private string _phone = string.Empty;
        public string Phone
        {
            get
            {
                if (_phone != string.Empty)
                {
                    return _phone;
                }

                if (_phoneAttrs.Length == 0)
                {
                    _phone = LdapAttrs.GetValue("phone");
                    return _phone;
                }

                _phone = _phoneAttrs
                    .Select(x => LdapAttrs.GetValue(x))
                    .FirstOrDefault(x => x != null) ?? LdapAttrs.GetValue("phone");

                return _phone;
            }
        }

        public ReadOnlyCollection<string> MemberOf => LdapAttrs.GetValues("memberOf");

        public ILdapAttributes LdapAttrs { get; private set; }

        private LdapProfile()
        {
            BaseDn = null;
            LdapAttrs = new LdapAttributes();
            _phoneAttrs = Array.Empty<string>();
        }

        public LdapProfile(LdapIdentity baseDn, ILdapAttributes attributes, IEnumerable<string> phoneAttrs)
        {
            if (phoneAttrs is null)
            {
                throw new ArgumentNullException(nameof(phoneAttrs));
            }

            BaseDn = baseDn ?? throw new ArgumentNullException(nameof(baseDn));
            LdapAttrs = attributes ?? throw new ArgumentNullException(nameof(attributes));
            _phoneAttrs = phoneAttrs.ToArray();
        }

        public static LdapProfile Empty() => new LdapProfile();   
        
        public void UpdateAttributes(ILdapAttributes attributes)
        {
            LdapAttrs = attributes ?? throw new ArgumentNullException(nameof(attributes));
        }
    }
}