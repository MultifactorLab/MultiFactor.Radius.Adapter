//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net;

namespace MultiFactor.Radius.Adapter
{
    /// <summary>
    /// Service configuration
    /// </summary>
    public class Configuration
    {
        public Configuration()
        {
            BypassSecondFactorWhenApiUnreachable = true; //by default
        }

        #region general settings

        /// <summary>
        /// This service RADIUS UDP Server endpoint
        /// </summary>
        public IPEndPoint ServiceServerEndpoint { get; set; }

        /// <summary>
        /// Shared secret between this service and Radius client
        /// </summary>
        public string RadiusSharedSecret { get; set; }

        /// <summary>
        /// Where to handle first factor (UserName and Password)
        /// </summary>
        public AuthenticationSource FirstFactorAuthenticationSource { get; set; }

        /// <summary>
        /// Bypass second factor within specified minutes period for same client-machine/user-name
        /// </summary>
        public int? BypassSecondFactorPeriod { get; set; }

        /// <summary>
        /// Bypass second factor when MultiFactor API is unreachable
        /// </summary>
        public bool BypassSecondFactorWhenApiUnreachable { get; set; }

        #endregion

        #region ActiveDirectory Authentication settings

        /// <summary>
        /// Active Directory Domain
        /// </summary>
        public string ActiveDirectoryDomain { get; set; }

        /// <summary>
        /// Only members of this group allowed to access (Optional)
        /// </summary>
        public string ActiveDirectoryGroup { get; set; }

        /// <summary>
        /// Only members of this group required to pass 2fa to access (Optional)
        /// </summary>
        public string ActiveDirectory2FaGroup { get; set; }

        /// <summary>
        /// Use ActiveDirectory User general properties phone number (Optional)
        /// </summary>
        public bool UseActiveDirectoryUserPhone { get; set; }

        /// <summary>
        /// Use ActiveDirectory User general properties mobile phone number (Optional)
        /// </summary>
        public bool UseActiveDirectoryMobileUserPhone { get; set; }

        /// <summary>
        /// Load user profile from AD and check group membership and 
        /// </summary>
        public bool CheckMembership
        {
            get
            {
                return ActiveDirectoryDomain != null &&
                    (ActiveDirectoryGroup != null || 
                    ActiveDirectory2FaGroup != null ||
                    UseActiveDirectoryUserPhone ||
                    UseActiveDirectoryMobileUserPhone);
            }
        }

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
        /// HTTP Proxy for API
        /// </summary>
        public string ApiProxy { get; set; }

        /// <summary>
        /// Multifactor API KEY
        /// </summary>
        public string NasIdentifier { get; set; }
        /// <summary>
        /// RADIUS Shared Secret
        /// </summary>
        public string MultiFactorSharedSecret { get; set; }
        /// <summary>
        /// Logging level
        /// </summary>
        public string LogLevel { get; set; }

        /// <summary>
        /// Custom RADIUS reply attributes
        /// </summary>
        public IDictionary<string, List<RadiusReplyAttributeValue>> RadiusReplyAttributes { get; set; }

        /// <summary>
        /// Read and load settings from appSettings configuration section
        /// </summary>
        public static Configuration Load(IRadiusDictionary dictionary)
        {
            if (dictionary == null)
            {
                throw new ArgumentNullException(nameof(dictionary));
            }
            
            var appSettings = ConfigurationManager.AppSettings;
            var serviceServerEndpointSetting = appSettings["adapter-server-endpoint"];
            var radiusSharedSecretSetting = appSettings["radius-shared-secret"];
            var firstFactorAuthenticationSourceSettings = appSettings["first-factor-authentication-source"];
            var apiUrlSetting = appSettings["multifactor-api-url"];
            var apiProxySetting = appSettings["multifactor-api-proxy"];
            var bypassSecondFactorPeriodSetting = appSettings["bypass-second-factor-period"];
            var bypassSecondFactorWhenApiUnreachableSetting = appSettings["bypass-second-factor-when-api-unreachable"];
            var nasIdentifierSetting = appSettings["multifactor-nas-identifier"];
            var multiFactorSharedSecretSetting = appSettings["multifactor-shared-secret"];
            var logLevelSetting = appSettings["logging-level"];

            if (string.IsNullOrEmpty(firstFactorAuthenticationSourceSettings))
            {
                throw new Exception("Configuration error: 'first-factor-authentication-source' element not found");
            }
            if (string.IsNullOrEmpty(serviceServerEndpointSetting))
            {
                throw new Exception("Configuration error: 'adapter-server-endpoint' element not found");
            }
            if (string.IsNullOrEmpty(radiusSharedSecretSetting))
            {
                throw new Exception("Configuration error: 'radius-shared-secret' element not found");
            }
            if (string.IsNullOrEmpty(apiUrlSetting))
            {
                throw new Exception("Configuration error: 'multifactor-api-url' element not found");
            }
            if (string.IsNullOrEmpty(nasIdentifierSetting))
            {
                throw new Exception("Configuration error: 'multifactor-nas-identifier' element not found");
            }
            if (string.IsNullOrEmpty(multiFactorSharedSecretSetting))
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
                RadiusSharedSecret = radiusSharedSecretSetting,
                FirstFactorAuthenticationSource = firstFactorAuthenticationSource,
                ApiUrl = apiUrlSetting,
                ApiProxy = apiProxySetting,
                NasIdentifier = nasIdentifierSetting,
                MultiFactorSharedSecret = multiFactorSharedSecretSetting,
                LogLevel = logLevelSetting
            };

            if (bypassSecondFactorPeriodSetting != null)
            {
                if (int.TryParse(bypassSecondFactorPeriodSetting, out var bypassSecondFactorPeriod))
                {
                    configuration.BypassSecondFactorPeriod = bypassSecondFactorPeriod;
                }
            }

            if (bypassSecondFactorWhenApiUnreachableSetting != null)
            {
                if (bool.TryParse(bypassSecondFactorWhenApiUnreachableSetting, out var bypassSecondFactorWhenApiUnreachable))
                {
                    configuration.BypassSecondFactorWhenApiUnreachable = bypassSecondFactorWhenApiUnreachable;
                }
            }

            switch (configuration.FirstFactorAuthenticationSource)
            {
                case AuthenticationSource.ActiveDirectory:
                    //active directory authentication and membership settings
                    LoadActiveDirectoryAuthenticationSourceSettings(configuration, true);
                    break;
                case AuthenticationSource.Radius:
                    //radius authentication settings
                    LoadRadiusAuthenticationSourceSettings(configuration);
                    break;
                case AuthenticationSource.None:
                    //active directory membership only settings
                    LoadActiveDirectoryAuthenticationSourceSettings(configuration, false);
                    break;
            }

            LoadRadiusReplyAttributes(configuration, dictionary);

            return configuration;
        }

        private static void LoadActiveDirectoryAuthenticationSourceSettings(Configuration configuration, bool mandatory)
        {
            var appSettings = ConfigurationManager.AppSettings;

            var activeDirectoryDomainSetting = appSettings["active-directory-domain"];
            var activeDirectoryGroupSetting = appSettings["active-directory-group"];
            var activeDirectory2FaGroupSetting = appSettings["active-directory-2fa-group"];
            var useActiveDirectoryUserPhoneSetting = appSettings["use-active-directory-user-phone"];
            var useActiveDirectoryMobileUserPhoneSetting = appSettings["use-active-directory-mobile-user-phone"];

            if (mandatory && string.IsNullOrEmpty(activeDirectoryDomainSetting))
            {
                throw new Exception("Configuration error: 'active-directory-domain' element not found");
            }

            if (!string.IsNullOrEmpty(useActiveDirectoryUserPhoneSetting))
            {
                if (!bool.TryParse(useActiveDirectoryUserPhoneSetting, out var useActiveDirectoryUserPhone))
                {
                    throw new Exception("Configuration error: Can't parse 'use-active-directory-user-phone' value");
                }

                configuration.UseActiveDirectoryUserPhone = useActiveDirectoryUserPhone;
            }

            if (!string.IsNullOrEmpty(useActiveDirectoryMobileUserPhoneSetting))
            {
                if (!bool.TryParse(useActiveDirectoryMobileUserPhoneSetting, out var useActiveDirectoryMobileUserPhone))
                {
                    throw new Exception("Configuration error: Can't parse 'use-active-directory-mobile-user-phone' value");
                }

                configuration.UseActiveDirectoryMobileUserPhone = useActiveDirectoryMobileUserPhone;
            }

            configuration.ActiveDirectoryDomain = activeDirectoryDomainSetting;
            configuration.ActiveDirectoryGroup = activeDirectoryGroupSetting;
            configuration.ActiveDirectory2FaGroup = activeDirectory2FaGroupSetting;
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

        private static void LoadRadiusReplyAttributes(Configuration configuration, IRadiusDictionary dictionary)
        {
            var replyAttributes = new Dictionary<string, List<RadiusReplyAttributeValue>>();
            var section = ConfigurationManager.GetSection("RadiusReply") as RadiusReplyAttributesSection;

            if (section != null)
            {
                foreach (var member in section.Members)
                {
                    var attribute = member as RadiusReplyAttributeElement;
                    var radiusAttribute = dictionary.GetAttribute(attribute.Name);
                    if (radiusAttribute == null)
                    {
                        throw new ConfigurationErrorsException($"Unknown attribute '{attribute.Name}' in RadiusReply configuration element, please see dictionary");
                    }
                    
                    if (!replyAttributes.ContainsKey(attribute.Name))
                    {
                        replyAttributes.Add(attribute.Name, new List<RadiusReplyAttributeValue>());
                    }

                    try
                    {
                        var value = ParseRadiusReplyAttributeValue(radiusAttribute, attribute.Value);
                        replyAttributes[attribute.Name].Add(new RadiusReplyAttributeValue(value, attribute.When));
                    }
                    catch (Exception ex)
                    {
                        throw new ConfigurationErrorsException($"Error while parsing attribute '{radiusAttribute.Name}' with {radiusAttribute.Type} value '{attribute.Value}' in RadiusReply configuration element: {ex.Message}");
                    }
                }
            }

            configuration.RadiusReplyAttributes = replyAttributes;
        }

        private static object ParseRadiusReplyAttributeValue(DictionaryAttribute attribute, string value)
        {
            switch (attribute.Type)
            {
                case DictionaryAttribute.TYPE_STRING:
                case DictionaryAttribute.TYPE_TAGGED_STRING:
                    return value;
                case DictionaryAttribute.TYPE_INTEGER:
                case DictionaryAttribute.TYPE_TAGGED_INTEGER:
                    return uint.Parse(value);
                case DictionaryAttribute.TYPE_IPADDR:
                    return IPAddress.Parse(value);
                case DictionaryAttribute.TYPE_OCTET:
                    return Utils.StringToByteArray(value);
                default:
                    throw new Exception($"Unknown type {attribute.Type}");
            }
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
        Radius,
        None
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

        [ConfigurationProperty("when", IsKey = false, IsRequired = false)]
        public string When
        {
            get { return (string)this["when"]; }
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
