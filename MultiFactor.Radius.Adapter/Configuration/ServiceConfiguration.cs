//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using Serilog;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Configuration;
using System.Net;
using System.Text;
using System.IO;
using NetTools;

namespace MultiFactor.Radius.Adapter.Configuration
{
    /// <summary>
    /// Service configuration
    /// </summary>
    public class ServiceConfiguration
    {
        /// <summary>
        /// List of clients with identification by client ip
        /// </summary>
        private IDictionary<IPAddress, ClientConfiguration> _ipClients;

        /// <summary>
        /// List of clients with identification by NAS-Identifier attr
        /// </summary>
        private IDictionary<string, ClientConfiguration> _nasIdClients;

        public ServiceConfiguration()
        {
            _ipClients = new Dictionary<IPAddress, ClientConfiguration>();
            _nasIdClients = new Dictionary<string, ClientConfiguration>();
        }

        private void AddClient(string nasId, ClientConfiguration client)
        {
            if (_nasIdClients.ContainsKey(nasId))
            {
                throw new ConfigurationErrorsException($"Client with NAS-Identifier '{nasId} already added from {_nasIdClients[nasId].Name}.config");
            }
            _nasIdClients.Add(nasId, client);
        }

        private void AddClient(IPAddress ip, ClientConfiguration client)
        {
            if (_ipClients.ContainsKey(ip))
            {
                throw new ConfigurationErrorsException($"Client with IP {ip} already added from {_ipClients[ip].Name}.config");
            }
            _ipClients.Add(ip, client);
        }

        public ClientConfiguration GetClient(string nasIdentifier)
        {
            if (SingleClientMode)
            {
                return _ipClients[IPAddress.Any];
            }
            if (string.IsNullOrEmpty(nasIdentifier))
            {
                return null;
            }
            if (_nasIdClients.ContainsKey(nasIdentifier))
            {
                return _nasIdClients[nasIdentifier];
            }
            return null;
        }

        public ClientConfiguration GetClient(IPAddress ip)
        {
            if (SingleClientMode)
            {
                return _ipClients[IPAddress.Any];
            }
            if (_ipClients.ContainsKey(ip))
            {
                return _ipClients[ip];
            }
            return null;
        }

        public ClientConfiguration GetClient(PendingRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }
            if (SingleClientMode)
            {
                return _ipClients[IPAddress.Any];
            }
            var nasId = request.RequestPacket.NasIdentifier;
            var ip = request.RemoteEndpoint.Address;
            return GetClient(nasId) ?? GetClient(ip);
        }

        /// <summary>
        /// Unique AD domains from all client confs
        /// </summary>
        public IList<string> GetAllActiveDirectoryDomains()
        {
            var ret = new List<string>();

            var part1 = _ipClients.Values
                .Where(client => client.ActiveDirectoryDomain != null)  //may check membership for radius and none of first factor
                .Select(client => client.ActiveDirectoryDomain);

            var part2 = _nasIdClients.Values
                .Where(client => client.ActiveDirectoryDomain != null)  //may check membership for radius and none of first factor
                .Select(client => client.ActiveDirectoryDomain);

            foreach (var part in part1.Union(part2))
            {
                var domains = part.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var domain in domains)
                {
                    ret.Add(domain.Trim());
                }
            }

            return ret.Distinct().ToArray();
        }

        #region general settings

        /// <summary>
        /// This service RADIUS UDP Server endpoint
        /// </summary>
        public IPEndPoint ServiceServerEndpoint { get; set; }

        /// <summary>
        /// Multifactor API URL
        /// </summary>
        public string ApiUrl { get; set; }
        /// <summary>
        /// HTTP Proxy for API
        /// </summary>
        public string ApiProxy { get; set; }

        /// <summary>
        /// Logging level
        /// </summary>
        public string LogLevel { get; set; }

        public bool SingleClientMode { get; set; }

        #endregion

        public static string GetLogFormat()
        {
            var appSettings = ConfigurationManager.AppSettings;
            return appSettings?["logging-format"];
        }

        #region load config section

        /// <summary>
        /// Read and load settings from appSettings configuration section
        /// </summary>
        public static ServiceConfiguration Load(IRadiusDictionary dictionary, ILogger logger)
        {
            if (dictionary == null)
            {
                throw new ArgumentNullException(nameof(dictionary));
            }

            var serviceConfig = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);

            var appSettingsSection = serviceConfig.GetSection("appSettings");
            var appSettings = appSettingsSection as AppSettingsSection;
            
            var serviceServerEndpointSetting    = appSettings.Settings["adapter-server-endpoint"]?.Value;
            var apiUrlSetting                   = appSettings.Settings["multifactor-api-url"]?.Value;
            var apiProxySetting                 = appSettings.Settings["multifactor-api-proxy"]?.Value;
            var logLevelSetting                 = appSettings.Settings["logging-level"]?.Value;

            if (string.IsNullOrEmpty(serviceServerEndpointSetting))
            {
                throw new Exception("Configuration error: 'adapter-server-endpoint' element not found");
            }
            if (string.IsNullOrEmpty(apiUrlSetting))
            {
                throw new Exception("Configuration error: 'multifactor-api-url' element not found");
            }
            if (string.IsNullOrEmpty(logLevelSetting))
            {
                throw new Exception("Configuration error: 'logging-level' element not found");
            }
            if (!TryParseIPEndPoint(serviceServerEndpointSetting, out var serviceServerEndpoint))
            {
                throw new Exception("Configuration error: Can't parse 'adapter-server-endpoint' value");
            }

            var configuration = new ServiceConfiguration
            {
                ServiceServerEndpoint = serviceServerEndpoint,
                ApiUrl = apiUrlSetting,
                ApiProxy = apiProxySetting,
                LogLevel = logLevelSetting
            };

            var clientConfigFilesPath = Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) + Path.DirectorySeparatorChar + "clients";
            var clientConfigFiles = Directory.Exists(clientConfigFilesPath) ? Directory.GetFiles(clientConfigFilesPath, "*.config") : new string[0];

            if (clientConfigFiles.Length == 0)
            {
                //check if we have anything
                var ffas = appSettings.Settings["first-factor-authentication-source"]?.Value;
                if (ffas == null)
                {
                    throw new ConfigurationErrorsException("No clients' config files found. Use one of the *.template files in the /clients folder to customize settings. Then save this file as *.config.");
                }

                var radiusReplyAttributesSection = ConfigurationManager.GetSection("RadiusReply") as RadiusReplyAttributesSection;
                var activeDirectorySection = ConfigurationManager.GetSection("ActiveDirectory") as ActiveDirectorySection;
                var userNameTransformRulesSection = ConfigurationManager.GetSection("UserNameTransformRules") as UserNameTransformRulesSection;

                var client = Load("General", dictionary, appSettings, radiusReplyAttributesSection, activeDirectorySection, userNameTransformRulesSection);
                configuration.AddClient(IPAddress.Any, client);
                configuration.SingleClientMode = true;
            }
            else
            {
                foreach (var clientConfigFile in clientConfigFiles)
                {
                    logger.Information($"Loading client configuration from {Path.GetFileName(clientConfigFile)}");

                    var customConfigFileMap = new ExeConfigurationFileMap();
                    customConfigFileMap.ExeConfigFilename = clientConfigFile;

                    var config = ConfigurationManager.OpenMappedExeConfiguration(customConfigFileMap, ConfigurationUserLevel.None);
                    var clientSettings = (AppSettingsSection)config.GetSection("appSettings");
                    var radiusReplyAttributesSection = config.GetSection("RadiusReply") as RadiusReplyAttributesSection;
                    var activeDirectorySection = config.GetSection("ActiveDirectory") as ActiveDirectorySection;
                    var userNameTransformRulesSection = config.GetSection("UserNameTransformRules") as UserNameTransformRulesSection;

                    var client = Load(Path.GetFileNameWithoutExtension(clientConfigFile), dictionary, clientSettings, radiusReplyAttributesSection, activeDirectorySection, userNameTransformRulesSection);

                    var radiusClientNasIdentifierSetting    = clientSettings.Settings["radius-client-nas-identifier"]?.Value;
                    var radiusClientIpSetting               = clientSettings.Settings["radius-client-ip"]?.Value;

                    if (!string.IsNullOrEmpty(radiusClientNasIdentifierSetting))
                    {
                        configuration.AddClient(radiusClientNasIdentifierSetting, client);
                        continue;
                    }

                    if (string.IsNullOrEmpty(radiusClientIpSetting))
                    {
                        throw new Exception("Configuration error: Either 'radius-client-nas-identifier' or 'radius-client-ip' must be configured");
                    }

                    var elements = radiusClientIpSetting.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var element in elements)
                    {
                        foreach (var ip in IPAddressRange.Parse(element))
                        {
                            configuration.AddClient(ip, client);
                        }
                    }
                }
            }

            return configuration;
        }

        public static ClientConfiguration Load(string name, IRadiusDictionary dictionary, AppSettingsSection appSettings, RadiusReplyAttributesSection radiusReplyAttributesSection, ActiveDirectorySection activeDirectorySection, UserNameTransformRulesSection userNameTransformRulesSection)
        {
            var radiusSharedSecretSetting                           = appSettings.Settings["radius-shared-secret"]?.Value;
            var radiusPapEncodingSetting                            = appSettings.Settings["radius-pap-encoding"]?.Value;
            var firstFactorAuthenticationSourceSettings             = appSettings.Settings["first-factor-authentication-source"]?.Value;
            var bypassSecondFactorWhenApiUnreachableSetting         = appSettings.Settings["bypass-second-factor-when-api-unreachable"]?.Value;
            var bypassSecondFactorPeriodSetting                     = appSettings.Settings["bypass-second-factor-period"]?.Value;
            var privacyModeSetting                                  = appSettings.Settings["privacy-mode"]?.Value;
            var multiFactorApiKeySetting                            = appSettings.Settings["multifactor-nas-identifier"]?.Value;
            var multiFactorApiSecretSetting                         = appSettings.Settings["multifactor-shared-secret"]?.Value;

            if (string.IsNullOrEmpty(firstFactorAuthenticationSourceSettings))
            {
                throw new Exception("Configuration error: 'first-factor-authentication-source' element not found");
            }

            if (string.IsNullOrEmpty(radiusSharedSecretSetting))
            {
                throw new Exception("Configuration error: 'radius-shared-secret' element not found");
            }

            if (string.IsNullOrEmpty(multiFactorApiKeySetting))
            {
                throw new Exception("Configuration error: 'multifactor-nas-identifier' element not found");
            }
            if (string.IsNullOrEmpty(multiFactorApiSecretSetting))
            {
                throw new Exception("Configuration error: 'multifactor-shared-secret' element not found");
            }

            if (!Enum.TryParse<AuthenticationSource>(firstFactorAuthenticationSourceSettings, true, out var firstFactorAuthenticationSource))
            {
                throw new Exception("Configuration error: Can't parse 'first-factor-authentication-source' value. Must be one of: ActiveDirectory, ADLDS, Radius, None");
            }

            if (!string.IsNullOrEmpty(radiusPapEncodingSetting))
            {
                try
                {
                    var customPapEncoding = Encoding.GetEncoding(radiusPapEncodingSetting);
                }
                catch
                {
                    throw new Exception($"Can't find encoding {radiusPapEncodingSetting}");
                }
            }

            var configuration = new ClientConfiguration
            {
                Name = name,
                RadiusSharedSecret = radiusSharedSecretSetting,
                RadiusPapEncoding = radiusPapEncodingSetting,
                FirstFactorAuthenticationSource = firstFactorAuthenticationSource,
                MultifactorApiKey = multiFactorApiKeySetting,
                MultiFactorApiSecret = multiFactorApiSecretSetting,
            };

            if (bypassSecondFactorWhenApiUnreachableSetting != null)
            {
                if (bool.TryParse(bypassSecondFactorWhenApiUnreachableSetting, out var bypassSecondFactorWhenApiUnreachable))
                {
                    configuration.BypassSecondFactorWhenApiUnreachable = bypassSecondFactorWhenApiUnreachable;
                }
            }

            if (bypassSecondFactorPeriodSetting != null)
            {
                if (int.TryParse(bypassSecondFactorPeriodSetting, out var bypassSecondFactorPeriod))
                {
                    configuration.BypassSecondFactorPeriod = bypassSecondFactorPeriod;
                }
            }

            if (!string.IsNullOrEmpty(privacyModeSetting))
            {
                if (!Enum.TryParse<PrivacyMode>(privacyModeSetting, true, out var privacyMode))
                {
                    throw new Exception("Configuration error: Can't parse 'privacy-mode' value. Must be one of: Full, None");
                }
                configuration.PrivacyMode = privacyMode;
            }

            switch (configuration.FirstFactorAuthenticationSource)
            {
                case AuthenticationSource.ActiveDirectory:
                    //active directory authentication and membership settings
                    LoadActiveDirectoryAuthenticationSourceSettings(configuration, appSettings, activeDirectorySection, true);
                    break;
                case AuthenticationSource.Radius:
                    //radius authentication settings
                    LoadRadiusAuthenticationSourceSettings(configuration, appSettings);
                    //active directory membership only settings
                    LoadActiveDirectoryAuthenticationSourceSettings(configuration, appSettings, activeDirectorySection, false);
                    break;
                case AuthenticationSource.AdLds:
                    LoadAdLdsAuthenticationSourceSettings(configuration, appSettings);
                    break;
                case AuthenticationSource.None:
                    //active directory membership only settings
                    LoadActiveDirectoryAuthenticationSourceSettings(configuration, appSettings, activeDirectorySection, false);
                    break;
            }

            LoadRadiusReplyAttributes(configuration, dictionary, radiusReplyAttributesSection);

            if (userNameTransformRulesSection?.Members != null)
            {
                foreach (var member in userNameTransformRulesSection?.Members)
                {
                    if (member is UserNameTransformRulesElement rule)
                    {
                        configuration.UserNameTransformRules.Add(rule);
                    }
                }
            }

            return configuration;
        }

        private static void LoadActiveDirectoryAuthenticationSourceSettings(ClientConfiguration configuration, AppSettingsSection appSettings, ActiveDirectorySection activeDirectorySection, bool mandatory)
        {
            var activeDirectoryDomainSetting                = appSettings.Settings["active-directory-domain"]?.Value;
            var activeDirectoryGroupSetting                 = appSettings.Settings["active-directory-group"]?.Value;
            var activeDirectory2FaGroupSetting              = appSettings.Settings["active-directory-2fa-group"]?.Value;
            var activeDirectory2FaBypassGroupSetting        = appSettings.Settings["active-directory-2fa-bypass-group"]?.Value;
            var useActiveDirectoryUserPhoneSetting          = appSettings.Settings["use-active-directory-user-phone"]?.Value;
            var useActiveDirectoryMobileUserPhoneSetting    = appSettings.Settings["use-active-directory-mobile-user-phone"]?.Value;
            var phoneAttributes                             = appSettings.Settings["phone-attribute"]?.Value;
            var loadActiveDirectoryNestedGroupsSettings     = appSettings.Settings["load-active-directory-nested-groups"]?.Value;
            var useUpnAsIdentitySetting                     = appSettings.Settings["use-upn-as-identity"]?.Value;

            if (mandatory && string.IsNullOrEmpty(activeDirectoryDomainSetting))
            {
                throw new Exception("Configuration error: 'active-directory-domain' element not found");
            }

            //legacy settings for general phone attribute usage
            if (bool.TryParse(useActiveDirectoryUserPhoneSetting, out var useActiveDirectoryUserPhone))
            {
                if (useActiveDirectoryUserPhone)
                {
                    configuration.PhoneAttributes.Add("telephoneNumber");
                }
            }

            //legacy settings for mobile phone attribute usage
            if (bool.TryParse(useActiveDirectoryMobileUserPhoneSetting, out var useActiveDirectoryMobileUserPhone))
            {
                if (useActiveDirectoryMobileUserPhone)
                {
                    configuration.PhoneAttributes.Add("mobile");
                }
            }

            if (!string.IsNullOrEmpty(phoneAttributes))
            {
                var attrs = phoneAttributes.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).Select(attr => attr.Trim()).ToList();
                configuration.PhoneAttributes = attrs;
            }

            if (!string.IsNullOrEmpty(loadActiveDirectoryNestedGroupsSettings))
            {
                if (!bool.TryParse(loadActiveDirectoryNestedGroupsSettings, out var loadActiveDirectoryNestedGroups))
                {
                    throw new Exception("Configuration error: Can't parse 'load-active-directory-nested-groups' value");
                }

                configuration.LoadActiveDirectoryNestedGroups = loadActiveDirectoryNestedGroups;
            }

            configuration.ActiveDirectoryDomain = activeDirectoryDomainSetting;

            if (!string.IsNullOrEmpty(activeDirectoryGroupSetting))
            {
                configuration.ActiveDirectoryGroup = activeDirectoryGroupSetting.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            }

            if (!string.IsNullOrEmpty(activeDirectory2FaGroupSetting))
            {
                configuration.ActiveDirectory2FaGroup = activeDirectory2FaGroupSetting.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            }

            if (!string.IsNullOrEmpty(activeDirectory2FaBypassGroupSetting))
            {
                configuration.ActiveDirectory2FaBypassGroup = activeDirectory2FaBypassGroupSetting.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            }

            if (bool.TryParse(useUpnAsIdentitySetting, out var useUpnAsIdentity))
            {
                configuration.UseUpnAsIdentity = useUpnAsIdentity;
            }

            if (activeDirectorySection != null)
            {
                var includedDomains = (from object value in activeDirectorySection.IncludedDomains
                                       select ((ValueElement)value).Name).ToList();
                var excludeddDomains = (from object value in activeDirectorySection.ExcludedDomains
                                        select ((ValueElement)value).Name).ToList();

                if (includedDomains.Count > 0 && excludeddDomains.Count > 0)
                {
                    throw new Exception("Both IncludedDomains and ExcludedDomains configured.");
                }

                configuration.IncludedDomains = includedDomains;
                configuration.ExcludedDomains = excludeddDomains;
                configuration.RequiresUpn = activeDirectorySection.RequiresUpn;
            }
        }

        private static void LoadAdLdsAuthenticationSourceSettings(ClientConfiguration configuration, AppSettingsSection appSettings)
        {
            var ldapUrlSetting = appSettings.Settings["ldap-url"]?.Value;

            if (string.IsNullOrEmpty(ldapUrlSetting))
            {
                throw new Exception("Configuration error: 'ldap-url' element not found");
            }

            if (!Uri.IsWellFormedUriString(ldapUrlSetting, UriKind.Absolute))
            {
                throw new Exception("Configuration error: 'ldap-url' element is not well formatted. See samples https://ldap.com/ldap-urls/");
            }

            configuration.LdapUrl = new Uri(ldapUrlSetting);
        }

        private static void LoadRadiusAuthenticationSourceSettings(ClientConfiguration configuration, AppSettingsSection appSettings)
        {
            var serviceClientEndpointSetting    = appSettings.Settings["adapter-client-endpoint"]?.Value;
            var npsEndpointSetting              = appSettings.Settings["nps-server-endpoint"]?.Value;

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

        private static void LoadRadiusReplyAttributes(ClientConfiguration configuration, IRadiusDictionary dictionary, RadiusReplyAttributesSection radiusReplyAttributesSection)
        {
            var replyAttributes = new Dictionary<string, List<RadiusReplyAttributeValue>>();

            if (radiusReplyAttributesSection != null)
            {
                foreach (var member in radiusReplyAttributesSection.Members)
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

                    if (!string.IsNullOrEmpty(attribute.From))
                    {
                        replyAttributes[attribute.Name].Add(new RadiusReplyAttributeValue(attribute.From));
                    }
                    else
                    {
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
            }

            configuration.RadiusReplyAttributes = replyAttributes;
        }

        private static object ParseRadiusReplyAttributeValue(DictionaryAttribute attribute, string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new Exception("Value must be specified");
            }

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

        #endregion

        #region static members

        /// <summary>
        /// Windows service unit name
        /// </summary>
        public static string ServiceUnitName
        {
            get
            {
                return ConfigurationManager.AppSettings["service-unit-name"] ?? "MFRadiusAdapter";
            }
        }

        /// <summary>
        /// Windows service display name
        /// </summary>
        public static string ServiceDisplayName
        {
            get
            {
                return ConfigurationManager.AppSettings["service-display-name"] ?? "MultiFactor Radius Adapter";
            }
        }

        #endregion
    }
}
