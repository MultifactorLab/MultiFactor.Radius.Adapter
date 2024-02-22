using System;

namespace MultiFactor.Radius.Adapter.Configuration.Features.PreAuthnModeFeature
{
    public class PreAuthnModeSettings
    {
        public int OtpCodeLength { get; }

        public PreAuthnModeSettings(int otpCodeLength)
        {
            if (otpCodeLength < 1 || otpCodeLength > 20)
            {
                throw new ArgumentOutOfRangeException(nameof(otpCodeLength), "Value should not be less than 1 and should not be more than 20");
            }
            OtpCodeLength = otpCodeLength;
        }

        public static PreAuthnModeSettings Default => new PreAuthnModeSettings(6);
    }
}
