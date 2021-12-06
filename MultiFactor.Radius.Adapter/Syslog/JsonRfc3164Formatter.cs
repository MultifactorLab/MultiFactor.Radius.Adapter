// Copyright 2018 Ionx Solutions (https://www.ionxsolutions.com)
// Ionx Solutions licenses this file to you under the Apache License,
// Version 2.0. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Compact;
using Serilog.Formatting.Display;
using Serilog.Sinks.Syslog;
using System;
using System.Globalization;
using System.IO;

namespace MultiFactor.Radius.Adapter.Syslog
{
    public class JsonRfc3164Formatter : SyslogFormatterBase
    {
        private readonly string applicationName;
        private ITextFormatter formatter = new RenderedCompactJsonFormatter();

        /// <summary>
        /// Initialize a new instance of <see cref="Rfc3164Formatter"/> class allowing you to specify values for
        /// the facility, application name and template formatter.
        /// </summary>
        /// <param name="facility"><inheritdoc cref="Facility" path="/summary"/></param>
        /// <param name="applicationName">A user supplied value representing the application name that will appear in the syslog event. Must be all printable ASCII characters. Max length 32. Defaults to the current process name.</param>
        /// <param name="templateFormatter"><inheritdoc cref="SyslogFormatterBase.templateFormatter" path="/summary"/></param>
        /// <param name="sourceHost"><inheritdoc cref="SyslogFormatterBase.Host" path="/summary"/></param>
        /// <param name="severityMapping"><inheritdoc cref="SyslogLoggerConfigurationExtensions.LocalSyslog" path="/param[@name='severityMapping']"/></param>
        public JsonRfc3164Formatter(Facility facility = Facility.Local0, string applicationName = null,
            MessageTemplateTextFormatter templateFormatter = null,
            string sourceHost = null)
            : base(facility, templateFormatter, sourceHost)
        {
            this.applicationName = applicationName ?? ProcessName;

            // Conform to the RFC
            this.applicationName = this.applicationName
                .AsPrintableAscii()
                .WithMaxLength(32);
        }

        public override string FormatMessage(LogEvent logEvent)
        {
            var priority = CalculatePriority(logEvent.Level);

            // This really is what RFC3164 specifies!
            // "The TIMESTAMP field is the local time and is in the format of "Mmm dd hh:mm:ss"
            // "If the day of the month is less than 10, then it MUST be represented as
            // a space and then the number"
            var dateFormat = logEvent.Timestamp.Day < 10
                ? "{0:MMM  d HH:mm:ss}"
                : "{0:MMM dd HH:mm:ss}";

            var timestamp = String.Format(CultureInfo.InvariantCulture, dateFormat, logEvent.Timestamp);

            // If the log event contains a source context, we will render it as part of the syslog CONTENT
            // field, as RFC3164 doesn't have anywhere else to put it
            var context = GetSourceContext(logEvent);

            string msg;
            using (var sw = new StringWriter())
            {
                formatter.Format(logEvent, sw);
                msg = sw.ToString().TrimEnd('\n', '\r'); ;
            }

            return context != null
                ? $"<{priority}>{timestamp} {this.Host} {this.applicationName}[{ProcessId}]: [{context}] {msg}"
                : $"<{priority}>{timestamp} {this.Host} {this.applicationName}[{ProcessId}]: {msg}";
        }

        /// <summary>
        /// Get the LogEvent's SourceContext in a format suitable for use as part of the CONTENT field
        /// of a syslog message (All Serilog property values are quoted and escaped, which is unnecessary
        /// here)
        /// </summary>
        /// <param name="logEvent">The LogEvent to extract the context from</param>
        /// <returns>The processed SourceContext</returns>
        private static string GetSourceContext(LogEvent logEvent)
        {
            var hasContext = logEvent.Properties.TryGetValue("SourceContext", out LogEventPropertyValue propertyValue);

            if (!hasContext)
                return null;

            // Trim surrounding quotes, and unescape all others
            var result = propertyValue
                .ToString()
                .TrimAndUnescapeQuotes();

            return result;
        }
    }
}
