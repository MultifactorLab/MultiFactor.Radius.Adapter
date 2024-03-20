//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;
using System.Text;

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi
{
    public class ApiAuthHeaderValue
    {
        public string Value { get; }

        public ApiAuthHeaderValue(string usr, string pwd)
        {
            if (string.IsNullOrEmpty(usr))
            {
                throw new ArgumentException($"'{nameof(usr)}' cannot be null or empty.", nameof(usr));
            }

            if (string.IsNullOrEmpty(pwd))
            {
                throw new ArgumentException($"'{nameof(pwd)}' cannot be null or empty.", nameof(pwd));
            }

            Value = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{usr}:{pwd}"));
        }
    }
}
