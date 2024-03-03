namespace MultiFactor.Radius.Adapter.Configuration.Features.PreAuthnModeFeature
{
    public enum PreAuthnMode
    {
        /// <summary>
        /// One-time password
        /// </summary>
        Otp,

        /// <summary>
        /// Mobile app push.
        /// </summary>
        Push,
        
        /// <summary>
        /// Telegram bot.
        /// </summary>
        Telegram,

        /// <summary>
        /// No mode specified
        /// </summary>
        None
    }
}
