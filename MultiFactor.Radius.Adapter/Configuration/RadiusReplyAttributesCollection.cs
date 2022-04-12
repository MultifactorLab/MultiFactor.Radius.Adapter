//Copyright(c) 2022 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System.Configuration;

namespace MultiFactor.Radius.Adapter.Configuration
{
    public class RadiusReplyAttributesCollection : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement()
        {
            return new RadiusReplyAttributeElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            var attribute = (RadiusReplyAttributeElement)element;
            return $"{attribute.Name}:{attribute.Value}:{attribute.From}";
        }
    }
}
