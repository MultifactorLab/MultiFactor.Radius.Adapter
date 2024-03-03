//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

namespace MultiFactor.Radius.Adapter.Server
{
    public enum AuthenticationCode
    {
        Awaiting,
        Accept,
        Reject,
        Bypass
    }
}