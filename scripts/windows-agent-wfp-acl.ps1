[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Provision", "Remove")]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$ServiceSid
)

$ErrorActionPreference = "Stop"

if ($ServiceSid -notmatch '^S-1-5-80-(\d+-){4}\d+$' -or $ServiceSid.Length -gt 128) {
    throw "A valid restricted Windows service SID is required for WFP ACL provisioning."
}

if (-not ("BlacklistInevitable.AgentWfpAclProvisioner" -as [type])) {
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace BlacklistInevitable {
    public static class AgentWfpAclProvisioner {
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const uint RPC_C_AUTHN_WINNT = 10;
        private const int GRANT_ACCESS = 1;
        private const int REVOKE_ACCESS = 4;
        private const int TRUSTEE_IS_SID = 0;
        private const int TRUSTEE_IS_USER = 1;
        private const int NO_MULTIPLE_TRUSTEE = 0;
        private const uint NO_INHERITANCE = 0;
        private const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;
        private const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;
        private const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
        private const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
        private const uint FWP_E_ALREADY_EXISTS = 0x80320009;

        private static readonly Guid ProviderKey =
            new Guid("9d45d56a-6b31-48aa-9c45-72c8b25e2f10");
        private static readonly Guid SublayerKey =
            new Guid("4aabbc48-c0a2-4f76-9f2a-0a90da1caa37");
        private static readonly Guid LayerV4 =
            new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        private static readonly Guid LayerV6 =
            new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

        [StructLayout(LayoutKind.Sequential)]
        private struct TrusteeW {
            public IntPtr pMultipleTrustee;
            public int MultipleTrusteeOperation;
            public int TrusteeForm;
            public int TrusteeType;
            public IntPtr ptstrName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExplicitAccessW {
            public uint grfAccessPermissions;
            public int grfAccessMode;
            public uint grfInheritance;
            public TrusteeW Trustee;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DisplayData0 {
            public IntPtr name;
            public IntPtr description;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByteBlob {
            public uint size;
            public IntPtr data;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Provider0 {
            public Guid providerKey;
            public DisplayData0 displayData;
            public uint flags;
            public ByteBlob providerData;
            public IntPtr serviceName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Sublayer0 {
            public Guid subLayerKey;
            public DisplayData0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public ByteBlob providerData;
            public ushort weight;
        }

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineOpen0(IntPtr serverName, uint authnService,
            IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineClose0(IntPtr engineHandle);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmTransactionCommit0(IntPtr engineHandle);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmProviderGetByKey0(IntPtr engineHandle,
            ref Guid key, out IntPtr provider);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmProviderAdd0(IntPtr engineHandle,
            ref Provider0 provider, IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmSubLayerGetByKey0(IntPtr engineHandle,
            ref Guid key, out IntPtr sublayer);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle,
            ref Sublayer0 sublayer, IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern void FwpmFreeMemory0(ref IntPtr pointer);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineGetSecurityInfo0(IntPtr engineHandle,
            uint securityInfo, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineSetSecurityInfo0(IntPtr engineHandle,
            uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmProviderGetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmProviderSetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmSubLayerGetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmSubLayerSetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmLayerGetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmLayerSetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmFilterGetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmFilterSetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern uint SetEntriesInAclW(uint count, ref ExplicitAccessW entries,
            IntPtr oldAcl, out IntPtr newAcl);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        private static IntPtr OpenEngine() {
            IntPtr engine;
            uint status = FwpmEngineOpen0(IntPtr.Zero, RPC_C_AUTHN_WINNT,
                IntPtr.Zero, IntPtr.Zero, out engine);
            if (status != 0 || engine == IntPtr.Zero)
                throw new InvalidOperationException(
                    "FwpmEngineOpen0 for Agent ACL provisioning failed: 0x" + status.ToString("X8"));
            return engine;
        }

        private static void EnsureProvider(IntPtr engine) {
            IntPtr pointer = IntPtr.Zero;
            Guid providerKey = ProviderKey;
            uint status = FwpmProviderGetByKey0(engine, ref providerKey, out pointer);
            if (status == 0) {
                try {
                    if (pointer == IntPtr.Zero)
                        throw new InvalidOperationException("WFP provider lookup returned NULL.");
                    Provider0 current = (Provider0)Marshal.PtrToStructure(pointer, typeof(Provider0));
                    if (current.providerKey != ProviderKey ||
                        (current.flags & FWPM_PROVIDER_FLAG_PERSISTENT) == 0)
                        throw new InvalidOperationException("The existing Agent WFP provider key is not the expected persistent provider.");
                    return;
                } finally {
                    if (pointer != IntPtr.Zero) FwpmFreeMemory0(ref pointer);
                }
            }
            if (status != FWP_E_PROVIDER_NOT_FOUND)
                throw new InvalidOperationException("FwpmProviderGetByKey0 failed: 0x" + status.ToString("X8"));

            IntPtr name = Marshal.StringToHGlobalUni("Blacklist Inevitable VPN Agent");
            try {
                Provider0 provider = new Provider0();
                provider.providerKey = ProviderKey;
                provider.displayData = new DisplayData0 { name = name, description = IntPtr.Zero };
                provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
                provider.providerData = new ByteBlob();
                provider.serviceName = IntPtr.Zero;
                uint add = FwpmProviderAdd0(engine, ref provider, IntPtr.Zero);
                if (add != 0 && add != FWP_E_ALREADY_EXISTS)
                    throw new InvalidOperationException("FwpmProviderAdd0 failed: 0x" + add.ToString("X8"));
            } finally {
                Marshal.FreeHGlobal(name);
            }

            pointer = IntPtr.Zero;
            status = FwpmProviderGetByKey0(engine, ref providerKey, out pointer);
            if (status != 0 || pointer == IntPtr.Zero)
                throw new InvalidOperationException("The Agent WFP provider could not be verified after creation: 0x" + status.ToString("X8"));
            try {
                Provider0 current = (Provider0)Marshal.PtrToStructure(pointer, typeof(Provider0));
                if (current.providerKey != ProviderKey ||
                    (current.flags & FWPM_PROVIDER_FLAG_PERSISTENT) == 0)
                    throw new InvalidOperationException("The created Agent WFP provider did not match the expected persistent identity.");
            } finally {
                FwpmFreeMemory0(ref pointer);
            }
        }

        private static void EnsureSublayer(IntPtr engine) {
            IntPtr pointer = IntPtr.Zero;
            Guid sublayerKey = SublayerKey;
            uint status = FwpmSubLayerGetByKey0(engine, ref sublayerKey, out pointer);
            if (status == 0) {
                try {
                    if (pointer == IntPtr.Zero)
                        throw new InvalidOperationException("WFP sublayer lookup returned NULL.");
                    Sublayer0 current = (Sublayer0)Marshal.PtrToStructure(pointer, typeof(Sublayer0));
                    Guid? owner = null;
                    if (current.providerKey != IntPtr.Zero)
                        owner = (Guid)Marshal.PtrToStructure(current.providerKey, typeof(Guid));
                    if (current.subLayerKey != SublayerKey ||
                        (current.flags & FWPM_SUBLAYER_FLAG_PERSISTENT) == 0 ||
                        owner != ProviderKey)
                        throw new InvalidOperationException("The existing Agent WFP sublayer is not owned by the expected persistent provider.");
                    return;
                } finally {
                    if (pointer != IntPtr.Zero) FwpmFreeMemory0(ref pointer);
                }
            }
            if (status != FWP_E_SUBLAYER_NOT_FOUND)
                throw new InvalidOperationException("FwpmSubLayerGetByKey0 failed: 0x" + status.ToString("X8"));

            IntPtr name = Marshal.StringToHGlobalUni("Blacklist Inevitable VPN egress policy");
            IntPtr providerKey = Marshal.AllocHGlobal(16);
            try {
                Marshal.StructureToPtr(ProviderKey, providerKey, false);
                Sublayer0 sublayer = new Sublayer0();
                sublayer.subLayerKey = SublayerKey;
                sublayer.displayData = new DisplayData0 { name = name, description = IntPtr.Zero };
                sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
                sublayer.providerKey = providerKey;
                sublayer.providerData = new ByteBlob();
                sublayer.weight = 0x7FFF;
                uint add = FwpmSubLayerAdd0(engine, ref sublayer, IntPtr.Zero);
                if (add != 0 && add != FWP_E_ALREADY_EXISTS)
                    throw new InvalidOperationException("FwpmSubLayerAdd0 failed: 0x" + add.ToString("X8"));
            } finally {
                Marshal.FreeHGlobal(providerKey);
                Marshal.FreeHGlobal(name);
            }

            pointer = IntPtr.Zero;
            status = FwpmSubLayerGetByKey0(engine, ref sublayerKey, out pointer);
            if (status != 0 || pointer == IntPtr.Zero)
                throw new InvalidOperationException("The Agent WFP sublayer could not be verified after creation: 0x" + status.ToString("X8"));
            try {
                Sublayer0 current = (Sublayer0)Marshal.PtrToStructure(pointer, typeof(Sublayer0));
                Guid? owner = null;
                if (current.providerKey != IntPtr.Zero)
                    owner = (Guid)Marshal.PtrToStructure(current.providerKey, typeof(Guid));
                if (current.subLayerKey != SublayerKey ||
                    (current.flags & FWPM_SUBLAYER_FLAG_PERSISTENT) == 0 ||
                    owner != ProviderKey)
                    throw new InvalidOperationException("The created Agent WFP sublayer did not match the expected persistent identity.");
            } finally {
                FwpmFreeMemory0(ref pointer);
            }
        }

        private static void EnsureNamespace(IntPtr engine) {
            uint begin = FwpmTransactionBegin0(engine, 0);
            if (begin != 0)
                throw new InvalidOperationException("FwpmTransactionBegin0 during Agent namespace provisioning failed: 0x" + begin.ToString("X8"));
            try {
                EnsureProvider(engine);
                EnsureSublayer(engine);
                uint commit = FwpmTransactionCommit0(engine);
                if (commit != 0)
                    throw new InvalidOperationException("FwpmTransactionCommit0 during Agent namespace provisioning failed: 0x" + commit.ToString("X8"));
            } catch {
                FwpmTransactionAbort0(engine);
                throw;
            }
        }

        private static IntPtr KeyPointer(string target) {
            Guid key;
            switch (target) {
                case "Provider": key = ProviderKey; break;
                case "Sublayer": key = SublayerKey; break;
                case "LayerV4": key = LayerV4; break;
                case "LayerV6": key = LayerV6; break;
                case "Engine":
                case "FilterContainer": return IntPtr.Zero;
                default: throw new ArgumentException("Unsupported WFP ACL target: " + target);
            }
            IntPtr pointer = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(key, pointer, false);
            return pointer;
        }

        private static uint ReadDacl(IntPtr engine, string target, IntPtr key,
            out IntPtr dacl, out IntPtr descriptor) {
            IntPtr owner, group, sacl;
            switch (target) {
                case "Engine":
                    return FwpmEngineGetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                        out owner, out group, out dacl, out sacl, out descriptor);
                case "Provider":
                    return FwpmProviderGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                        out owner, out group, out dacl, out sacl, out descriptor);
                case "Sublayer":
                    return FwpmSubLayerGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                        out owner, out group, out dacl, out sacl, out descriptor);
                case "LayerV4":
                case "LayerV6":
                    return FwpmLayerGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                        out owner, out group, out dacl, out sacl, out descriptor);
                case "FilterContainer":
                    return FwpmFilterGetSecurityInfoByKey0(engine, IntPtr.Zero, DACL_SECURITY_INFORMATION,
                        out owner, out group, out dacl, out sacl, out descriptor);
                default: throw new ArgumentException("Unsupported WFP ACL target: " + target);
            }
        }

        private static uint WriteDacl(IntPtr engine, string target, IntPtr key, IntPtr dacl) {
            switch (target) {
                case "Engine":
                    return FwpmEngineSetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                        IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                case "Provider":
                    return FwpmProviderSetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                        IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                case "Sublayer":
                    return FwpmSubLayerSetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                        IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                case "LayerV4":
                case "LayerV6":
                    return FwpmLayerSetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                        IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                case "FilterContainer":
                    return FwpmFilterSetSecurityInfoByKey0(engine, IntPtr.Zero, DACL_SECURITY_INFORMATION,
                        IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                default: throw new ArgumentException("Unsupported WFP ACL target: " + target);
            }
        }

        private static void ChangeServiceAce(IntPtr engine, string target,
            string serviceSid, uint accessMask, bool grant, bool allowMissing) {
            IntPtr key = KeyPointer(target);
            IntPtr descriptor = IntPtr.Zero;
            IntPtr dacl = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            IntPtr newAcl = IntPtr.Zero;
            try {
                uint read = ReadDacl(engine, target, key, out dacl, out descriptor);
                if (allowMissing && ((target == "Provider" && read == FWP_E_PROVIDER_NOT_FOUND) ||
                    (target == "Sublayer" && read == FWP_E_SUBLAYER_NOT_FOUND)))
                    return;
                if (read != 0 || descriptor == IntPtr.Zero)
                    throw new InvalidOperationException("Could not read " + target + " WFP DACL: 0x" + read.ToString("X8"));
                if (dacl == IntPtr.Zero)
                    throw new InvalidOperationException(target + " WFP object has a NULL DACL; refusing ACL mutation.");
                if (!ConvertStringSidToSidW(serviceSid, out sid))
                    throw new InvalidOperationException("ConvertStringSidToSidW failed: " + Marshal.GetLastWin32Error());

                ExplicitAccessW entry = new ExplicitAccessW();
                entry.grfAccessPermissions = accessMask;
                entry.grfAccessMode = grant ? GRANT_ACCESS : REVOKE_ACCESS;
                entry.grfInheritance = NO_INHERITANCE;
                entry.Trustee = new TrusteeW {
                    pMultipleTrustee = IntPtr.Zero,
                    MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE,
                    TrusteeForm = TRUSTEE_IS_SID,
                    TrusteeType = TRUSTEE_IS_USER,
                    ptstrName = sid
                };
                uint aclStatus = SetEntriesInAclW(1, ref entry, dacl, out newAcl);
                if (aclStatus != 0 || newAcl == IntPtr.Zero)
                    throw new InvalidOperationException("SetEntriesInAclW for " + target + " failed: 0x" + aclStatus.ToString("X8"));
                uint write = WriteDacl(engine, target, key, newAcl);
                if (write != 0)
                    throw new InvalidOperationException("Could not update " + target + " WFP DACL: 0x" + write.ToString("X8"));
            } finally {
                if (newAcl != IntPtr.Zero) LocalFree(newAcl);
                if (sid != IntPtr.Zero) LocalFree(sid);
                if (descriptor != IntPtr.Zero) FwpmFreeMemory0(ref descriptor);
                if (key != IntPtr.Zero) Marshal.FreeHGlobal(key);
            }
        }

        private static readonly string[] Targets = new string[] {
            "Engine", "Provider", "Sublayer", "LayerV4", "LayerV6", "FilterContainer"
        };
        private static readonly uint[] Rights = new uint[] {
            0x00000008, 0x00000082, 0x00000082, 0x00000002, 0x00000002, 0x00000001
        };

        public static string Provision(string serviceSid) {
            IntPtr engine = OpenEngine();
            List<string> touched = new List<string>();
            try {
                EnsureNamespace(engine);
                for (int i = 0; i < Targets.Length; i++) {
                    // Service SIDs are unique to this service. Revoke only this
                    // SID's old ACEs before writing the exact non-inheriting grant.
                    touched.Add(Targets[i]);
                    ChangeServiceAce(engine, Targets[i], serviceSid, Rights[i], false, false);
                    ChangeServiceAce(engine, Targets[i], serviceSid, Rights[i], true, false);
                }
                return "Provisioned six object-scoped WFP ACEs for the restricted Agent service SID.";
            } catch {
                for (int i = touched.Count - 1; i >= 0; i--) {
                    try {
                        int index = Array.IndexOf(Targets, touched[i]);
                        ChangeServiceAce(engine, touched[i], serviceSid, Rights[index], false, true);
                    } catch { }
                }
                throw;
            } finally {
                FwpmEngineClose0(engine);
            }
        }

        public static string Remove(string serviceSid) {
            IntPtr engine = OpenEngine();
            List<string> failures = new List<string>();
            try {
                for (int i = Targets.Length - 1; i >= 0; i--) {
                    try {
                        ChangeServiceAce(engine, Targets[i], serviceSid, Rights[i], false, true);
                    } catch (Exception error) {
                        failures.Add(Targets[i] + ": " + error.Message);
                    }
                }
            } finally {
                FwpmEngineClose0(engine);
            }
            if (failures.Count != 0)
                throw new InvalidOperationException("One or more Agent WFP ACEs could not be removed: " + String.Join("; ", failures.ToArray()));
            return "Removed the restricted Agent service SID's WFP ACEs; persistent Agent provider/sublayer metadata was left untouched.";
        }
    }
}
'@
}

if ($Action -eq "Provision") {
    [BlacklistInevitable.AgentWfpAclProvisioner]::Provision($ServiceSid)
} else {
    [BlacklistInevitable.AgentWfpAclProvisioner]::Remove($ServiceSid)
}
