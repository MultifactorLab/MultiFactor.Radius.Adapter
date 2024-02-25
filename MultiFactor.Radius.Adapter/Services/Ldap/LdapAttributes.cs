using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    internal class LdapAttributes : ILdapAttributes
    {
        private readonly Dictionary<string, List<string>> _attrs;

        public ReadOnlyCollection<string> Keys => new ReadOnlyCollection<string>(_attrs.Keys.ToList());

        public LdapAttributes() 
        { 
            _attrs = new Dictionary<string, List<string>>();
        }

        public LdapAttributes(ILdapAttributes source) 
        {
            if (source is null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if (source is LdapAttributes ldapAttributes) 
            {
                _attrs = ldapAttributes._attrs;
                return;
            }

            _attrs = new Dictionary<string, List<string>>();
            foreach (var attr in source.Keys)
            {
                _attrs[attr] = new List<string>(source.GetValues(attr));
            }
        }

        public bool Has(string attribute)
        {
            if (attribute is null)
            {
                throw new ArgumentNullException(nameof(attribute));
            }
            // ToLower(CultureInfo.InvariantCulture) - same as in the native DirectoryServices search result entry.
            return _attrs.ContainsKey(attribute.ToLower(CultureInfo.InvariantCulture));
        }

        public string GetValue(string attribute)
        {
            if (attribute is null)
            {
                throw new ArgumentNullException(nameof(attribute));
            }

            var attr = attribute.ToLower(CultureInfo.InvariantCulture);
            if (!_attrs.ContainsKey(attr))
            {
                return default;
            }

            return _attrs[attr].FirstOrDefault();
        }

        public ReadOnlyCollection<string> GetValues(string attribute)
        {
            if (attribute is null)
            {
                throw new ArgumentNullException(nameof(attribute));
            }

            var attr = attribute.ToLower(CultureInfo.InvariantCulture);

            if (!_attrs.ContainsKey(attr))
            {
                return new ReadOnlyCollection<string>(Array.Empty<string>());
            }

            return _attrs[attr].AsReadOnly();
        }

        public LdapAttributes Add(string attribute, IEnumerable<string> value)
        {
            if (attribute is null)
            {
                throw new ArgumentNullException(nameof(attribute));
            }

            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var attr = attribute.ToLower(CultureInfo.InvariantCulture);
            if (!_attrs.ContainsKey(attr))
            {
                _attrs[attr] = new List<string>();
            }

            _attrs[attr].AddRange(value);
            return this;
        }
        
        public LdapAttributes Remove(string attribute)
        {
            if (attribute is null)
            {
                throw new ArgumentNullException(nameof(attribute));
            }

            var attr = attribute.ToLower(CultureInfo.InvariantCulture);
            if (_attrs.ContainsKey(attr))
            {
                _attrs[attr].Remove(attribute);
            }

            return this;
        }
        
        public LdapAttributes Replace(string attribute, IEnumerable<string> value)
        {
            if (attribute is null)
            {
                throw new ArgumentNullException(nameof(attribute));
            }

            var attr = attribute.ToLower(CultureInfo.InvariantCulture);
            _attrs[attr] = new List<string>(value);
            
            return this;
        }
    }
}