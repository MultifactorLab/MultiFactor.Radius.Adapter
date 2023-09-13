using System;
using System.DirectoryServices.AccountManagement;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class LdapIdentity
    {
        public string Name { get; set; }
        public string NetBiosName { get; private set; } = string.Empty;
        public IdentityType Type { get; set; }
        public string TypeName
        {
            get
            {
                switch (Type)
                {
                    case IdentityType.DistinguishedName:
                        return "distinguishedName";
                    case IdentityType.SamAccountName:
                        return "sAMAccountName";
                    case IdentityType.UserPrincipalName:
                        return "userPrincipalName";
                    default:
                        return "name";
                }
            }
        }

        public static LdapIdentity ParseUser(string name)
        {
            return Parse(name, true);
        }
        
        public static LdapIdentity ParseGroup(string name)
        {
            return Parse(name, false);
        }
        
        /// <summary>
        /// Converts domain.local to DC=domain,DC=local
        /// </summary>
        public static LdapIdentity FqdnToDn(string name)
        {
            if (string.IsNullOrEmpty(name)) throw new ArgumentNullException(nameof(name));

            var portIndex = name.IndexOf(":");
            if (portIndex > 0)
            {
                name = name.Substring(0, portIndex);
            }

            var domains = name.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
            var dn = domains.Select(p => $"DC={p}").ToArray();

            return new LdapIdentity
            {
                Name = string.Join(",", dn),
                Type = IdentityType.DistinguishedName
            };
        }

        /// <summary>
        /// Extracts CN from DN
        /// </summary>
        public static string DnToCn(string dn)
        {
            return dn.Split(',')[0].Split(new[] { '=' })[1];
        }

        /// <summary>
        /// DC part from DN
        /// </summary>
        public static LdapIdentity BaseDn(string dn)
        {
            var ncs = dn.Split(new[] { ',' } , StringSplitOptions.RemoveEmptyEntries);
            var baseDn = ncs.Where(nc => nc.ToLower().StartsWith("dc="));
            return new LdapIdentity
            {
                Type = IdentityType.DistinguishedName,
                Name = string.Join(",", baseDn)
            };
        }

        private static LdapIdentity Parse(string name, bool isUser)
        {
            if (string.IsNullOrEmpty(name)) throw new ArgumentNullException(nameof(name));

            var identity = name.ToLower();
            string netBiosName = string.Empty;
            //remove DOMAIN\\ prefix
            var type = IdentityType.SamAccountName;
            var index = identity.IndexOf("\\");
            if (index > 0)
            {
                type = IdentityType.SamAccountName;
                netBiosName = identity.Substring(0, index);
                identity = identity.Substring(index + 1);
            }

            if (identity.Contains("="))
            {
                type = IdentityType.DistinguishedName;
            }
            else if (identity.Contains("@"))
            {
                type = IdentityType.UserPrincipalName;
            }

            return new LdapIdentity
            {
                Name = identity,
                Type = type,
                NetBiosName = netBiosName,
            };
        }

        public string DnToFqdn()
        {
            var ncs = Name.Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries);
            var fqdn = ncs.Select(nc => nc.Split(new[] { '=' }, StringSplitOptions.RemoveEmptyEntries)[1].TrimEnd(','));
            return string.Join(".", fqdn);
        }

        public bool IsChildOf(LdapIdentity parent)
        {
            return Name != parent.Name && Name.EndsWith(parent.Name);
        }

        public string UpnToSuffix()
        {
            if (Type != IdentityType.UserPrincipalName)
            {
                throw new InvalidOperationException($"Invalid username format: {Name}. Expected UPN");
            }

            var index = Name.IndexOf("@");
            return Name.Substring(index + 1).ToLower();
        }

        public void SetNetBiosName(string netbiosName)
        {
            NetBiosName = netbiosName;
        }

        public bool HasNetbiosName() => !string.IsNullOrEmpty(NetBiosName);

        public override string ToString()
        {
            return Name;
        }
    }
}
