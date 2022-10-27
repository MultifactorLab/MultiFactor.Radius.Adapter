//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System.ComponentModel;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory
{
    public enum LdapErrorReason
    {
        [Description("525")]
        UserNotFound,
        
        [Description("52e")]
        InvalidCredentials,
        
        [Description("530")]
        NotPermittedToLogonAtThisTime,
        
        [Description("531")]
        NotPermittedToLogonAtThisWorkstation​,
        
        [Description("532")]
        PasswordExpired,
        
        [Description("533")]
        AccountDisabled,
        
        [Description("701")]
        AccountExpired,
        
        [Description("773")]
        UserMustChangePassword,
        
        [Description("775")]
        UserAccountLocked,

        UnknownError
    }
}