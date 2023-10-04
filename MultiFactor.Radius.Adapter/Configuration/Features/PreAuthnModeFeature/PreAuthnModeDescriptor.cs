using System;

namespace MultiFactor.Radius.Adapter.Configuration.Features.PreAuthnModeFeature
{
    public class PreAuthnModeDescriptor
    {
        public PreAuthnMode Mode { get; }

        private PreAuthnModeDescriptor(PreAuthnMode mode)
        {
            Mode = mode;
        }

        public static PreAuthnModeDescriptor Create(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return new PreAuthnModeDescriptor(PreAuthnMode.None);
            var mode = GetMode(value);

            return new PreAuthnModeDescriptor(mode);
        }

        private static PreAuthnMode GetMode(string value)
        {
            Enum.TryParse<PreAuthnMode>(value, true, out var parsed);
            return parsed;
        }
    }
}
