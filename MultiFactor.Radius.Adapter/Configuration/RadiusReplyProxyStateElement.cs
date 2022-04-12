//Copyright(c) 2022 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;
using System.Configuration;

namespace MultiFactor.Radius.Adapter.Configuration
{
    public class RadiusReplyProxyStateElement : ConfigurationElement
    {
        [ConfigurationProperty("remove", IsKey = false, IsRequired = true)]
        public bool Remove
        {
            get { return (bool)this["remove"]; }
        }
    }
}
