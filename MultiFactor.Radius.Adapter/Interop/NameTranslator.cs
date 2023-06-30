using Serilog;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static MultiFactor.Radius.Adapter.Interop.NativeMethods;

namespace MultiFactor.Radius.Adapter.Interop
{
    public class NameTranslator : IDisposable
    {
        private readonly SafeDsHandle _handle;
        private readonly ILogger _logger;
        private readonly string _domain;

        public NameTranslator(string domain, ILogger logger)
        {
            _domain = domain;
            _logger = logger;
            uint res = DsBind(domain, null, out _handle);
            if (res != (uint)DS_NAME_ERROR.DS_NAME_NO_ERROR)
            {
                _logger.Warning($"Failed to bind to: {domain}");
                throw new Win32Exception((int)res);
            }
        }

        public string Translate(string netbiosName)
        {
            uint err = DsCrackNames(_handle, DS_NAME_FLAGS.DS_NAME_FLAG_EVAL_AT_DC | DS_NAME_FLAGS.DS_NAME_FLAG_TRUST_REFERRAL, DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME, DS_NAME_FORMAT.DS_USER_PRINCIPAL_NAME, 1, new[] { netbiosName }, out IntPtr pResult);
            if (err != (uint)DS_NAME_ERROR.DS_NAME_NO_ERROR)
            {
                _logger.Warning($"Failed to translate {netbiosName} in {_domain}");
                throw new Win32Exception((int)err);
            }

            try
            {
                // Next convert the returned structure to managed environment
                DS_NAME_RESULT Result = (DS_NAME_RESULT)Marshal.PtrToStructure(pResult, typeof(DS_NAME_RESULT));
                var res = Result.Items;
                if (res == null || res.Length == 0 || (!res[0].status.HasFlag(DS_NAME_ERROR.DS_NAME_ERROR_TRUST_REFERRAL) && !res[0].status.HasFlag(DS_NAME_ERROR.DS_NAME_NO_ERROR)))
                {
                    _logger.Warning($"Unexpected result of translation {netbiosName} in {_domain}");
                    throw new System.Security.SecurityException("Unable to resolve user name.");
                }
                return res[0].pDomain;
            }
            finally
            {
                DsFreeNameResult(pResult);
            }

        }

        public void Dispose()
        {
            _handle.Dispose();
        }
    }
}
