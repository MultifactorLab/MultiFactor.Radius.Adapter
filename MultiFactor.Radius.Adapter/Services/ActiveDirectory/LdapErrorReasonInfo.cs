//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text.RegularExpressions;

namespace MultiFactor.Radius.Adapter.Services.ActiveDirectory
{
    public class LdapErrorReasonInfo
    {
        public LdapErrorFlag Flags { get; }
        public LdapErrorReason Reason { get; }
        public string ReasonText { get; }

        protected LdapErrorReasonInfo(LdapErrorReason reason, LdapErrorFlag flags, string reasonText)
        {
            Flags = flags;
            Reason = reason;
            ReasonText = reasonText;
        }

        public static LdapErrorReasonInfo Create(LdapException exception)
        {
            if (exception is null)
            {
                throw new ArgumentNullException(nameof(exception));
            }

            var reason = GetErrorReason(exception.Message);
            var flags = GetErrorFlags(reason);
            var text = GetReasonText(reason);

            return new LdapErrorReasonInfo(reason, flags, text);
        }

        private static LdapErrorReason GetErrorReason(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return LdapErrorReason.UnknownError;
            }

            var pattern = @"data ([0-9a-e]{3})";
            var match = Regex.Match(message, pattern);

            if (!match.Success || match.Groups.Count != 2)
            {
                return LdapErrorReason.UnknownError;
            }

            var data = match.Groups[1].Value;
            switch (data)
            {
                case "525": return LdapErrorReason.UserNotFound;
                case "52e": return LdapErrorReason.InvalidCredentials;
                case "530": return LdapErrorReason.NotPermittedToLogonAtThisTime;
                case "531": return LdapErrorReason.NotPermittedToLogonAtThisWorkstation;
                case "532": return LdapErrorReason.PasswordExpired;
                case "533": return LdapErrorReason.AccountDisabled;
                case "701": return LdapErrorReason.AccountExpired;
                case "773": return LdapErrorReason.UserMustChangePassword;
                case "775": return LdapErrorReason.UserAccountLocked;
                default: return LdapErrorReason.UnknownError;
            }
        }

        private static LdapErrorFlag GetErrorFlags(LdapErrorReason reason)
        {
            switch (reason)
            {
                case LdapErrorReason.PasswordExpired:
                case LdapErrorReason.UserMustChangePassword:
                    return LdapErrorFlag.MustChangePassword;
                default: 
                    return LdapErrorFlag.Empty;
            }
        }

        private static string GetReasonText(LdapErrorReason reason)
        {
            // "SomeErrorText" -> ["some, "error", "text"]
            var splitted = Regex.Split(reason.ToString(), @"(?<!^)(?=[A-Z])").Select(x => x.ToLower());
            return string.Join(" ", splitted);
        }
    }
}