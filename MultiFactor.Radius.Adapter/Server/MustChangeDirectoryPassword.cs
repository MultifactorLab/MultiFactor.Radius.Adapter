//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;

namespace MultiFactor.Radius.Adapter.Server
{
    public class MustChangePassword
    {
        public string Domain { get; }

        public MustChangePassword(string domain) 
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentException($"'{nameof(domain)}' cannot be null or whitespace.", nameof(domain));
            }

            Domain = domain;
        }
    }
}