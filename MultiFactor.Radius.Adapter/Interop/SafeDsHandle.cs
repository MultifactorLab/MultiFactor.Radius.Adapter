using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace MultiFactor.Radius.Adapter.Interop
{
    public class SafeDsHandle : SafeHandle
    {
        public SafeDsHandle() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid
        {
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            [PrePrepareMethod]
            get { return (handle == IntPtr.Zero); }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [PrePrepareMethod]

        protected override bool ReleaseHandle()
        {
            uint ret = NativeMethods.DsUnBind(ref handle);
            System.Diagnostics.Debug.WriteLineIf(ret != 0, "Error unbinding :\t" + ret.ToString());
            return ret != 0;
        }
    }
}
