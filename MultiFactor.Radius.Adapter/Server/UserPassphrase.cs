//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration.Features.PreAuthnModeFeature;
using MultiFactor.Radius.Adapter.Core;
using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace MultiFactor.Radius.Adapter.Server
{
    public class UserPassphrase
    {
        private static readonly string[] _providerCodes = { "t", "m", "s", "c" };

        public string Raw { get; }

        /// <summary>
        /// User password.
        /// </summary>
        public string Password { get; }

        /// <summary>
        /// 6 digits.
        /// </summary>
        public string Otp { get; }

        /// <summary>
        /// Maybe one of 't', 'm', 's' or 'c'.
        /// <para>
        /// t: Telegram
        /// </para>
        /// <para>
        /// m: MobileApp
        /// </para>
        /// <para>
        ///  s: SMS
        /// </para>
        /// <para>
        ///  c: PhoneCall
        /// </para>
        /// </summary>
        public string ProviderCode { get; }

        /// <summary>
        /// User-Password packet attribute is empty.
        /// </summary>
        public bool IsEmpty => Password == null && Otp == null && ProviderCode == null;

        private UserPassphrase(string raw, string password, string otp, string providerCode)
        {
            Raw = raw;
            Password = password;
            Otp = otp;
            ProviderCode = providerCode;
        }

        public static UserPassphrase Parse(IRadiusPacket packet, PreAuthnModeDescriptor preAuthnMode) 
        {
            if (packet is null)
            {
                throw new ArgumentNullException(nameof(packet));
            }

            if (preAuthnMode is null)
            {
                throw new ArgumentNullException(nameof(preAuthnMode));
            }

            if (!TryGetOtpCode(packet, preAuthnMode, out var otp))
            {
                otp = null;
            }

            var pwd = GetPassword(packet, preAuthnMode);
            if (string.IsNullOrEmpty(pwd))
            {
                pwd = null;
            }

            var provCode = _providerCodes.FirstOrDefault(x => x == pwd?.ToLower());
            return new UserPassphrase(packet.TryGetUserPassword(), pwd, otp, provCode);
        }

        private static string GetPassword(IRadiusPacket packet, PreAuthnModeDescriptor preAuthnMode)
        {
            var passwordAndOtp = packet.TryGetUserPassword()?.Trim() ?? string.Empty;
            switch (preAuthnMode.Mode)
            {
                case PreAuthnMode.Otp:
                    var length = preAuthnMode.Settings.OtpCodeLength;
                    if (passwordAndOtp.Length < length)
                    {
                        return passwordAndOtp;
                    }

                    var sub = passwordAndOtp.Substring(0, passwordAndOtp.Length - length);
                    if (!Regex.IsMatch(sub, preAuthnMode.Settings.OtpCodeRegex))
                    {
                        return passwordAndOtp;
                    }

                    return sub;

                case PreAuthnMode.None:
                default:
                    return passwordAndOtp;
            }
        } 

        private static bool TryGetOtpCode(IRadiusPacket packet, PreAuthnModeDescriptor preAuthnMode, out string code)
        {
            if (preAuthnMode.Mode != PreAuthnMode.Otp)
            {
                code = null;
                return false;
            }

            var passwordAndOtp = packet.TryGetUserPassword()?.Trim() ?? string.Empty;
            var length = preAuthnMode.Settings.OtpCodeLength;
            if (passwordAndOtp.Length < length)
            {
                code = null;
                return false;
            }

            code = passwordAndOtp.Substring(passwordAndOtp.Length - length);
            if (!Regex.IsMatch(code, preAuthnMode.Settings.OtpCodeRegex))
            {
                code = null;
                return false;
            }

            return true;
        }
    }
}