//Copyright(c) 2022 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using System.Configuration;

//do not change namespace for backward compatibility with older versions
namespace MultiFactor.Radius.Adapter
{
    public class RadiusReplyAttributesSection : ConfigurationSection
    {
        [ConfigurationProperty("Attributes")]
        public RadiusReplyAttributesCollection Members
        {
            get { return (RadiusReplyAttributesCollection)this["Attributes"]; }
        }

        [ConfigurationProperty("ProxyState")]
        public RadiusReplyProxyStateElement ProxyState
        {
            get
            {
                return (RadiusReplyProxyStateElement)this["ProxyState"];
            }
        }
    }
}
