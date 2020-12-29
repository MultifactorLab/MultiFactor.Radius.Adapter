namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public class LdapProfile
    {
        public string DistinguishedName { get; set; }
        public string DisplayName { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
        public string Mobile { get; set; }

        public LdapIdentity BaseDn { get; set; }
    }
}
