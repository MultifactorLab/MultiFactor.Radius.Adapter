//Copyright(c) 2022 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System.Configuration;

namespace MultiFactor.Radius.Adapter
{
    public class UserNameTransformRulesCollection : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement()
        {
            return new UserNameTransformRulesElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            var attribute = (UserNameTransformRulesElement)element;
            return $"{attribute.Match}:{attribute.Replace}";
        }
    }
}
