//Copyright(c) 2022 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System.Configuration;

namespace MultiFactor.Radius.Adapter
{
    public class UserNameTransformRulesElement : ConfigurationElement
    {
        [ConfigurationProperty("match", IsKey = false, IsRequired = true)]
        public string Match
        {
            get { return (string)this["match"]; }
        }

        [ConfigurationProperty("replace", IsKey = false, IsRequired = true)]
        public string Replace
        {
            get { return (string)this["replace"]; }
        }

        [ConfigurationProperty("count", IsKey = false, IsRequired = false)]
        public int? Count
        {
            get { return (int?)this["count"]; }
        }
    }
}
