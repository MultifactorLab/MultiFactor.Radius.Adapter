//Copyright(c) 2022 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System.Configuration;

namespace MultiFactor.Radius.Adapter.Configuration
{
    public class RadiusReplyAttributeElement : ConfigurationElement
    {
        [ConfigurationProperty("name", IsKey = false, IsRequired = true)]
        public string Name
        {
            get { return (string)this["name"]; }
        }

        [ConfigurationProperty("value", IsKey = false, IsRequired = false)]
        public string Value
        {
            get { return (string)this["value"]; }
        }

        [ConfigurationProperty("when", IsKey = false, IsRequired = false)]
        public string When
        {
            get { return (string)this["when"]; }
        }

        [ConfigurationProperty("from", IsKey = false, IsRequired = false)]
        public string From
        {
            get { return (string)this["from"]; }
        }
    }
}
