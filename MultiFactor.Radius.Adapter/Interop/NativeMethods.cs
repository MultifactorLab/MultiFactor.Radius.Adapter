using System;
using System.Runtime.InteropServices;

namespace MultiFactor.Radius.Adapter.Interop
{
    internal static class NativeMethods
    {
        private const string NTDSAPI = "ntdsapi.dll";

        [DllImport(NTDSAPI, CharSet = CharSet.Auto)]
        public static extern uint DsBind(
           string DomainControllerName, // in, optional
           string DnsDomainName, // in, optional
           out SafeDsHandle phDS);

        [DllImport(NTDSAPI, CharSet = CharSet.Auto)]
        public static extern uint DsCrackNames(
            SafeDsHandle hDS,
            DS_NAME_FLAGS flags,
            DS_NAME_FORMAT formatOffered,
            DS_NAME_FORMAT formatDesired,
            uint cNames,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPTStr, SizeParamIndex = 4)]
                string[] rpNames,
            out IntPtr ppResult);

        [DllImport(NTDSAPI, CharSet = CharSet.Auto)]
        public static extern void DsFreeNameResult(IntPtr pResult /* DS_NAME_RESULT* */);

        [DllImport(NTDSAPI, CharSet = CharSet.Auto)]
        public static extern uint DsUnBind(ref IntPtr phDS);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct DS_NAME_RESULT
        {
            public uint cItems;
            internal IntPtr rItems; // PDS_NAME_RESULT_ITEM
            public DS_NAME_RESULT_ITEM[] Items
            {
                get
                {
                    if (rItems == IntPtr.Zero)
                    {
                        return new DS_NAME_RESULT_ITEM[0];
                    }

                    var ResultArray = new DS_NAME_RESULT_ITEM[cItems];
                    Type strType = typeof(DS_NAME_RESULT_ITEM);
                    int stSize = Marshal.SizeOf(strType);
                    IntPtr curptr;

                    for (uint i = 0; i < cItems; i++)
                    {
                        curptr = new IntPtr(rItems.ToInt64() + (i * stSize));
                        ResultArray[i] = (DS_NAME_RESULT_ITEM)Marshal.PtrToStructure(curptr, strType);
                    }
                    return ResultArray;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct DS_NAME_RESULT_ITEM
        {
            public DS_NAME_ERROR status;
            public string pDomain;
            public string pName;
            public override string ToString()
            {
                if (status == DS_NAME_ERROR.DS_NAME_NO_ERROR)
                {
                    return pName;
                }

                return null;
            }
        }

        public enum DS_NAME_ERROR
        {
            DS_NAME_NO_ERROR = 0,
            // Generic processing error.
            DS_NAME_ERROR_RESOLVING = 1,
            // Couldn't find the name at all - or perhaps caller doesn't have
            // rights to see it.
            DS_NAME_ERROR_NOT_FOUND = 2,
            // Input name mapped to more than one output name.
            DS_NAME_ERROR_NOT_UNIQUE = 3,
            // Input name found, but not the associated output format.
            // Can happen if object doesn't have all the required attributes.
            DS_NAME_ERROR_NO_MAPPING = 4,
            // Unable to resolve entire name, but was able to determine which
            // domain object resides in.  Thus DS_NAME_RESULT_ITEM?.pDomain
            // is valid on return.
            DS_NAME_ERROR_DOMAIN_ONLY = 5,
            // Unable to perform a purely syntactical mapping at the client
            // without going out on the wire.
            DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING = 6,
            // The name is from an external trusted forest.
            DS_NAME_ERROR_TRUST_REFERRAL = 7
        }

        [Flags]
        public enum DS_NAME_FLAGS
        {
            DS_NAME_NO_FLAGS = 0x0,
            // Perform a syntactical mapping at the client (if possible) without
            // going out on the wire.  Returns DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING
            // if a purely syntactical mapping is not possible.
            DS_NAME_FLAG_SYNTACTICAL_ONLY = 0x1,
            // Force a trip to the DC for evaluation, even if this could be
            // locally cracked syntactically.
            DS_NAME_FLAG_EVAL_AT_DC = 0x2,
            // The call fails if the DC is not a GC
            DS_NAME_FLAG_GCVERIFY = 0x4,
            // Enable cross forest trust referral
            DS_NAME_FLAG_TRUST_REFERRAL = 0x8
        }

        public enum DS_NAME_FORMAT
        {
            // unknown name type
            DS_UNKNOWN_NAME = 0,
            // eg: CN=User Name,OU=Users,DC=Example,DC=Microsoft,DC=Com
            DS_FQDN_1779_NAME = 1,
            // eg: Example\UserN
            // Domain-only version includes trailing '\\'.
            DS_NT4_ACCOUNT_NAME = 2,
            // Probably "User Name" but could be something else.  I.e. The
            // display name is not necessarily the defining RDN.
            DS_DISPLAY_NAME = 3,
            // obsolete - see #define later
            // DS_DOMAIN_SIMPLE_NAME = 4,
            // obsolete - see #define later
            // DS_ENTERPRISE_SIMPLE_NAME = 5,
            // String-ized GUID as returned by IIDFromString().
            // eg: {4fa050f0-f561-11cf-bdd9-00aa003a77b6}
            DS_UNIQUE_ID_NAME = 6,
            // eg: example.microsoft.com/software/user name
            // Domain-only version includes trailing '/'.
            DS_CANONICAL_NAME = 7,
            // eg: usern@example.microsoft.com
            DS_USER_PRINCIPAL_NAME = 8,
            // Same as DS_CANONICAL_NAME except that rightmost '/' is
            // replaced with '\n' - even in domain-only case.
            // eg: example.microsoft.com/software\nuser name
            DS_CANONICAL_NAME_EX = 9,
            // eg: www/www.microsoft.com@example.com - generalized service principal
            // names.
            DS_SERVICE_PRINCIPAL_NAME = 10,
            // This is the string representation of a SID.  Invalid for formatDesired.
            // See sddl.h for SID binary <--> text conversion routines.
            // eg: S-1-5-21-397955417-626881126-188441444-501
            DS_SID_OR_SID_HISTORY_NAME = 11,
            // Pseudo-name format so GetUserNameEx can return the DNS domain name to
            // a caller.  This level is not supported by the DS APIs.
            DS_DNS_DOMAIN_NAME = 12
        }
    }
}
