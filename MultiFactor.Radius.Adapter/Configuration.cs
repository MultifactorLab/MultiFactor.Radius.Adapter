using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Net;

namespace MultiFactor.Radius.Adapter
{
    /// <summary>
    /// Service configuration
    /// </summary>
    public class Configuration
    {
        /// <summary>
        /// This service RADIUS UDP Server endpoint
        /// </summary>
        public IPEndPoint ServiceServerEndpoint { get; set; }

        /// <summary>
        /// Where to handle first factor (UserName and Password)
        /// </summary>
        public AuthenticationSource FirstFactorAuthenticationSource { get; set; }

        #region ActiveDirectory Authentication settings

        /// <summary>
        /// Active Directory Domain
        /// </summary>
        public string ActiveDirectoryDomain { get; set; }

        #endregion

        #region RADIUS Authentication settings

        /// <summary>
        /// This service RADIUS UDP Client endpoint
        /// </summary>
        public IPEndPoint ServiceClientEndpoint { get; set; }
        /// <summary>
        /// Network Policy Service RADIUS UDP Server endpoint
        /// </summary>
        public IPEndPoint NpsServerEndpoint { get; set; }

        #endregion

        /// <summary>
        /// Multifactor API URL
        /// </summary>
        public string ApiUrl { get; set; }
        /// <summary>
        /// Multifactor API KEY
        /// </summary>
        public string NasIdentifier { get; set; }
        /// <summary>
        /// RADIUS Shared Secret
        /// </summary>
        public string SharedSecret { get; set; }
        /// <summary>
        /// Logging level
        /// </summary>
        public string LogLevel { get; set; }

        /// <summary>
        /// Custom RADIUS reply attributes
        /// </summary>
        public IDictionary<string, List<object>> RadiusReplyAttributes { get; set; }

        /// <summary>
        /// Read and load settings from appSettings configuration section
        /// </summary>
        public static Configuration Load()
        {
            var appSettings = ConfigurationManager.AppSettings;
            var serviceServerEndpointSetting = appSettings["adapter-server-endpoint"];
            var firstFactorAuthenticationSourceSettings = appSettings["first-factor-authentication-source"];
            var apiUrlSetting = appSettings["multifactor-api-url"];
            var nasIdentifierSetting = appSettings["multifactor-nas-identifier"];
            var sharedSecretSetting = appSettings["multifactor-shared-secret"];
            var logLevelSetting = appSettings["logging-level"];

            if (string.IsNullOrEmpty(firstFactorAuthenticationSourceSettings))
            {
                throw new Exception("Configuration error: 'first-factor-authentication-source' element not found");
            }
            if (string.IsNullOrEmpty(serviceServerEndpointSetting))
            {
                throw new Exception("Configuration error: 'adapter-server-endpoint' element not found");
            }
            if (string.IsNullOrEmpty(apiUrlSetting))
            {
                throw new Exception("Configuration error: 'multifactor-api-url' element not found");
            }
            if (string.IsNullOrEmpty(nasIdentifierSetting))
            {
                throw new Exception("Configuration error: 'multifactor-nas-identifier' element not found");
            }
            if (string.IsNullOrEmpty(sharedSecretSetting))
            {
                throw new Exception("Configuration error: 'multifactor-shared-secret' element not found");
            }
            if (string.IsNullOrEmpty(logLevelSetting))
            {
                throw new Exception("Configuration error: 'logging-level' element not found");
            }

            if (!Enum.TryParse<AuthenticationSource>(firstFactorAuthenticationSourceSettings, out var firstFactorAuthenticationSource))
            {
                throw new Exception("Configuration error: Can't parse 'first-factor-authentication-source' value. Must be one of: ActiveDirectory, Radius");
            }
            if (!TryParseIPEndPoint(serviceServerEndpointSetting, out var serviceServerEndpoint))
            {
                throw new Exception("Configuration error: Can't parse 'adapter-server-endpoint' value");
            }


            var configuration = new Configuration
            {
                ServiceServerEndpoint = serviceServerEndpoint,
                FirstFactorAuthenticationSource = firstFactorAuthenticationSource,
                ApiUrl = apiUrlSetting,
                NasIdentifier = nasIdentifierSetting,
                SharedSecret = sharedSecretSetting,
                LogLevel = logLevelSetting
            };

            switch(configuration.FirstFactorAuthenticationSource)
            {
                case AuthenticationSource.ActiveDirectory:
                    LoadActiveDirectoryAuthenticationSourceSettings(configuration);
                    break;
                case AuthenticationSource.Radius:
                    LoadRadiusAuthenticationSourceSettings(configuration);
                    break;
                default:
                    throw new NotImplementedException(configuration.FirstFactorAuthenticationSource.ToString());
            }

            LoadRadiusReplyAttributes(configuration);

            return configuration;
        }

        private static void LoadActiveDirectoryAuthenticationSourceSettings(Configuration configuration)
        {
            var appSettings = ConfigurationManager.AppSettings;

            var activeDirectoryDomainSetting = appSettings["active-directory-domain"];

            if (string.IsNullOrEmpty(activeDirectoryDomainSetting))
            {
                throw new Exception("Configuration error: 'active-directory-domain' element not found");
            }

            configuration.ActiveDirectoryDomain = activeDirectoryDomainSetting;
        }

        private static void LoadRadiusAuthenticationSourceSettings(Configuration configuration)
        {
            var appSettings = ConfigurationManager.AppSettings;
            
            var serviceClientEndpointSetting = appSettings["adapter-client-endpoint"];
            var npsEndpointSetting = appSettings["nps-server-endpoint"];

            if (string.IsNullOrEmpty(serviceClientEndpointSetting))
            {
                throw new Exception("Configuration error: 'adapter-client-endpoint' element not found");
            }
            if (string.IsNullOrEmpty(npsEndpointSetting))
            {
                throw new Exception("Configuration error: 'nps-server-endpoint' element not found");
            }

            if (!TryParseIPEndPoint(serviceClientEndpointSetting, out var serviceClientEndpoint))
            {
                throw new Exception("Configuration error: Can't parse 'adapter-client-endpoint' value");
            }
            if (!TryParseIPEndPoint(npsEndpointSetting, out var npsEndpoint))
            {
                throw new Exception("Configuration error: Can't parse 'nps-server-endpoint' value");
            }

            configuration.ServiceClientEndpoint = serviceClientEndpoint;
            configuration.NpsServerEndpoint = npsEndpoint;
        }

        private static void LoadRadiusReplyAttributes(Configuration configuration)
        {
            var replyAttributes = new Dictionary<string, List<object>>();

            var section = ConfigurationManager.GetSection("RadiusReply") as RadiusReplyAttributesSection;

            if (section != null)
            {
                foreach (var member in section.Members)
                {
                    var attribute = member as RadiusReplyAttributeElement;
                    if (!replyAttributes.ContainsKey(attribute.Name))
                    {
                        replyAttributes.Add(attribute.Name, new List<object>());
                    }

                    replyAttributes[attribute.Name].Add(attribute.Value);
                }
            }

            configuration.RadiusReplyAttributes = replyAttributes;
        }

        private static bool TryParseIPEndPoint(string text, out IPEndPoint ipEndPoint)
        {
            Uri uri;
            ipEndPoint = null;

            if (Uri.TryCreate(string.Concat("tcp://", text), UriKind.Absolute, out uri))
            {
                ipEndPoint = new IPEndPoint(IPAddress.Parse(uri.Host), uri.Port < 0 ? 0 : uri.Port);
                return true;
            }
            if (Uri.TryCreate(string.Concat("tcp://", string.Concat("[", text, "]")), UriKind.Absolute, out uri))
            {
                ipEndPoint = new IPEndPoint(IPAddress.Parse(uri.Host), uri.Port < 0 ? 0 : uri.Port);
                return true;
            }

            throw new FormatException($"Failed to parse {text} to IPEndPoint");
        }
    }

    public enum AuthenticationSource
    {
        ActiveDirectory,
        Radius
    }

    public class RadiusReplyAttributeElement : ConfigurationElement
    {
        [ConfigurationProperty("name", IsKey = false, IsRequired = true)]
        public string Name
        {
            get { return (string)this["name"]; }
        }

        [ConfigurationProperty("value", IsKey = false, IsRequired = true)]
        public string Value
        {
            get { return (string)this["value"]; }
        }
    }

    public class RadiusReplyAttributesCollection : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement()
        {
            return new RadiusReplyAttributeElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            var attribute = (RadiusReplyAttributeElement)element;
            return $"{attribute.Name}:{attribute.Value}";
        }
    }

    public class RadiusReplyAttributesSection : ConfigurationSection
    {
        [ConfigurationProperty("Attributes")]
        public RadiusReplyAttributesCollection Members
        {
            get { return (RadiusReplyAttributesCollection)this["Attributes"]; }
        }
    }
}
