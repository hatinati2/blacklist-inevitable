[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AgentPath
)

$ErrorActionPreference = "Stop"
$serviceName = "BlacklistInevitableAgent"
$probeRoot = Join-Path $env:ProgramFiles "BlacklistInevitableWfpProbe"
$probeExe = Join-Path $probeRoot "blacklist-inevitable-wfp-acl-probe.exe"
$stateRoot = Join-Path $env:ProgramData "blacklist-inevitable"
$reportDirectory = Join-Path $stateRoot "Agent"
$reportPath = Join-Path $reportDirectory "wfp-acl-probe.json"
$serviceSidPath = Join-Path $reportDirectory "wfp-acl-probe-service-sid.txt"
$artifactPath = Join-Path $env:RUNNER_TEMP "wfp-service-sid-probe.json"
$serviceCreated = $false
$aclMutationAttempted = $false
$originalDacls = @{}

# Run only on the disposable elevated GitHub-hosted runner.
# The administrator BFE smoke test must have provisioned the Agent provider
# and sublayer before this script starts. No provider/sublayer containers or
# unrelated WFP objects are modified here.
if (-not ("BlacklistInevitable.WfpScopedAclInterop" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace BlacklistInevitable {
    public static class WfpScopedAclInterop {
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const uint RPC_C_AUTHN_WINNT = 10;
        private const int GRANT_ACCESS = 1;
        private const int TRUSTEE_IS_SID = 0;
        private const int TRUSTEE_IS_USER = 1;
        private const int NO_MULTIPLE_TRUSTEE = 0;
        private const uint NO_INHERITANCE = 0;

        private static readonly Guid ProviderKey =
            new Guid("9d45d56a-6b31-48aa-9c45-72c8b25e2f10");
        private static readonly Guid SublayerKey =
            new Guid("4aabbc48-c0a2-4f76-9f2a-0a90da1caa37");
        private static readonly Guid LayerV4 =
            new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        private static readonly Guid LayerV6 =
            new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        private static readonly Guid OutboundTransportV4 =
            new Guid("09e61aea-d214-46e2-9b21-b26b0b2f28c8");
        private static readonly Guid OutboundTransportV6 =
            new Guid("e1735bde-013f-4655-b351-a49e15762df0");

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

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineOpen0(IntPtr serverName, uint authnService,
            IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineClose0(IntPtr engineHandle);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineGetSecurityInfo0(IntPtr engineHandle,
            uint securityInfo, out IntPtr sidOwner, out IntPtr sidGroup,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineSetSecurityInfo0(IntPtr engineHandle,
            uint securityInfo, IntPtr sidOwner, IntPtr sidGroup, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmProviderGetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, out IntPtr sidOwner, out IntPtr sidGroup,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmProviderSetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, IntPtr sidOwner, IntPtr sidGroup, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmSubLayerGetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, out IntPtr sidOwner, out IntPtr sidGroup,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmSubLayerSetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, IntPtr sidOwner, IntPtr sidGroup, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmLayerGetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, out IntPtr sidOwner, out IntPtr sidGroup,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmLayerSetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, IntPtr sidOwner, IntPtr sidGroup, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmFilterGetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, out IntPtr sidOwner, out IntPtr sidGroup,
            out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmFilterSetSecurityInfoByKey0(IntPtr engineHandle,
            IntPtr key, uint securityInfo, IntPtr sidOwner, IntPtr sidGroup, IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern void FwpmFreeMemory0(ref IntPtr pointer);
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
                    "FwpmEngineOpen0 for scoped ACL provisioning failed: 0x" + status.ToString("X8"));
            return engine;
        }

        private static IntPtr KeyPointer(string target) {
            Guid key;
            switch (target) {
                case "Provider": key = ProviderKey; break;
                case "Sublayer": key = SublayerKey; break;
                case "LayerV4": key = LayerV4; break;
                case "LayerV6": key = LayerV6; break;
                case "OutboundTransportV4": key = OutboundTransportV4; break;
                case "OutboundTransportV6": key = OutboundTransportV6; break;
                case "Engine":
                case "FilterContainer":
                    return IntPtr.Zero;
                default:
                    throw new ArgumentException("Unsupported WFP ACL target: " + target);
            }
            IntPtr pointer = Marshal.AllocHGlobal(16);
            byte[] bytes = key.ToByteArray();
            Marshal.Copy(bytes, 0, pointer, 16);
            return pointer;
        }

        private static byte[] ReadDacl(IntPtr engine, string target) {
            IntPtr key = KeyPointer(target);
            IntPtr owner, group, dacl, sacl, descriptor;
            uint status;
            try {
                switch (target) {
                    case "Engine":
                        status = FwpmEngineGetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                            out owner, out group, out dacl, out sacl, out descriptor);
                        break;
                    case "Provider":
                        status = FwpmProviderGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                            out owner, out group, out dacl, out sacl, out descriptor);
                        break;
                    case "Sublayer":
                        status = FwpmSubLayerGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                            out owner, out group, out dacl, out sacl, out descriptor);
                        break;
                    case "LayerV4":
                    case "LayerV6":
                    case "OutboundTransportV4":
                    case "OutboundTransportV6":
                        status = FwpmLayerGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                            out owner, out group, out dacl, out sacl, out descriptor);
                        break;
                    case "FilterContainer":
                        status = FwpmFilterGetSecurityInfoByKey0(engine, IntPtr.Zero, DACL_SECURITY_INFORMATION,
                            out owner, out group, out dacl, out sacl, out descriptor);
                        break;
                    default:
                        throw new ArgumentException("Unsupported WFP ACL target: " + target);
                }
            }
            finally {
                if (target != "Engine" && target != "FilterContainer" && key != IntPtr.Zero)
                    Marshal.FreeHGlobal(key);
            }

            if (status != 0 || descriptor == IntPtr.Zero)
                throw new InvalidOperationException(
                    "Could not read " + target + " WFP DACL: 0x" + status.ToString("X8"));
            try {
                // A NULL DACL grants unrestricted access. Never replace one.
                if (dacl == IntPtr.Zero)
                    throw new InvalidOperationException(target + " WFP object has a NULL DACL; refusing ACL mutation.");
                int size = unchecked((ushort)Marshal.ReadInt16(IntPtr.Add(dacl, 2)));
                if (size < 8)
                    throw new InvalidOperationException(target + " WFP DACL has an invalid ACL size.");
                byte[] bytes = new byte[size];
                Marshal.Copy(dacl, bytes, 0, size);
                return bytes;
            }
            finally {
                FwpmFreeMemory0(ref descriptor);
            }
        }

        private static void SetDacl(IntPtr engine, string target, byte[] bytes) {
            IntPtr key = KeyPointer(target);
            IntPtr acl = Marshal.AllocHGlobal(bytes.Length);
            try {
                Marshal.Copy(bytes, 0, acl, bytes.Length);
                uint status;
                switch (target) {
                    case "Engine":
                        status = FwpmEngineSetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                            IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                        break;
                    case "Provider":
                        status = FwpmProviderSetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                            IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                        break;
                    case "Sublayer":
                        status = FwpmSubLayerSetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                            IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                        break;
                    case "LayerV4":
                    case "LayerV6":
                    case "OutboundTransportV4":
                    case "OutboundTransportV6":
                        status = FwpmLayerSetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                            IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                        break;
                    case "FilterContainer":
                        status = FwpmFilterSetSecurityInfoByKey0(engine, IntPtr.Zero, DACL_SECURITY_INFORMATION,
                            IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                        break;
                    default:
                        throw new ArgumentException("Unsupported WFP ACL target: " + target);
                }
                if (status != 0)
                    throw new InvalidOperationException(
                        "Could not set " + target + " WFP DACL: 0x" + status.ToString("X8"));
            }
            finally {
                if (target != "Engine" && target != "FilterContainer" && key != IntPtr.Zero)
                    Marshal.FreeHGlobal(key);
                Marshal.FreeHGlobal(acl);
            }
        }

        public static string CaptureDaclBase64(string target) {
            IntPtr engine = OpenEngine();
            try { return Convert.ToBase64String(ReadDacl(engine, target)); }
            finally { FwpmEngineClose0(engine); }
        }

        public static void AddTemporaryServiceAce(string target, string serviceSid, uint accessMask) {
            IntPtr engine = OpenEngine();
            IntPtr descriptor = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            IntPtr newAcl = IntPtr.Zero;
            try {
                // Snapshot here as an additional guard against applying a grant
                // to a NULL or unreadable security descriptor.
                byte[] ignored = ReadDacl(engine, target);
                IntPtr key = KeyPointer(target);
                IntPtr owner, group, dacl, sacl;
                uint readStatus;
                try {
                    switch (target) {
                        case "Engine":
                            readStatus = FwpmEngineGetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                                out owner, out group, out dacl, out sacl, out descriptor);
                            break;
                        case "Provider":
                            readStatus = FwpmProviderGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                                out owner, out group, out dacl, out sacl, out descriptor);
                            break;
                        case "Sublayer":
                            readStatus = FwpmSubLayerGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                                out owner, out group, out dacl, out sacl, out descriptor);
                            break;
                        case "LayerV4":
                        case "LayerV6":
                        case "OutboundTransportV4":
                        case "OutboundTransportV6":
                            readStatus = FwpmLayerGetSecurityInfoByKey0(engine, key, DACL_SECURITY_INFORMATION,
                                out owner, out group, out dacl, out sacl, out descriptor);
                            break;
                        case "FilterContainer":
                            readStatus = FwpmFilterGetSecurityInfoByKey0(engine, IntPtr.Zero, DACL_SECURITY_INFORMATION,
                                out owner, out group, out dacl, out sacl, out descriptor);
                            break;
                        default:
                            throw new ArgumentException("Unsupported WFP ACL target: " + target);
                    }
                }
                finally {
                    if (target != "Engine" && target != "FilterContainer" && key != IntPtr.Zero)
                        Marshal.FreeHGlobal(key);
                }
                if (readStatus != 0 || descriptor == IntPtr.Zero || dacl == IntPtr.Zero)
                    throw new InvalidOperationException(
                        "Could not retrieve " + target + " WFP DACL before grant: 0x" + readStatus.ToString("X8"));
                if (!ConvertStringSidToSidW(serviceSid, out sid))
                    throw new InvalidOperationException(
                        "ConvertStringSidToSidW failed: " + Marshal.GetLastWin32Error());

                ExplicitAccessW entry = new ExplicitAccessW();
                entry.grfAccessPermissions = accessMask;
                entry.grfAccessMode = GRANT_ACCESS;
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
                    throw new InvalidOperationException("SetEntriesInAclW failed: 0x" + aclStatus.ToString("X8"));

                // Build a byte copy so one common setter path handles every target.
                int size = unchecked((ushort)Marshal.ReadInt16(IntPtr.Add(newAcl, 2)));
                byte[] updated = new byte[size];
                Marshal.Copy(newAcl, updated, 0, size);
                SetDacl(engine, target, updated);
            }
            finally {
                if (newAcl != IntPtr.Zero) LocalFree(newAcl);
                if (sid != IntPtr.Zero) LocalFree(sid);
                if (descriptor != IntPtr.Zero) FwpmFreeMemory0(ref descriptor);
                FwpmEngineClose0(engine);
            }
        }

        public static void RestoreDaclBase64(string target, string base64Dacl) {
            byte[] bytes = Convert.FromBase64String(base64Dacl);
            if (bytes.Length < 8)
                throw new InvalidOperationException("The captured " + target + " DACL is invalid.");
            IntPtr engine = OpenEngine();
            try { SetDacl(engine, target, bytes); }
            finally { FwpmEngineClose0(engine); }
        }
    }
}
'@
}

function Invoke-Icacls {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = & (Join-Path $env:WINDIR "System32\icacls.exe") @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls failed: $($output -join ' ')" }
}

$aclRights = [ordered]@{
    Engine = [uint32]0x00000008       # BEGIN_WRITE_TXN, non-inheriting
    Provider = [uint32]0x00000082     # READ | ADD_LINK on Agent provider only
    Sublayer = [uint32]0x00000082     # READ | ADD_LINK on Agent sublayer only
    LayerV4 = [uint32]0x00000002      # ADD_LINK on ALE_AUTH_CONNECT_V4 only
    LayerV6 = [uint32]0x00000002      # ADD_LINK on ALE_AUTH_CONNECT_V6 only
    OutboundTransportV4 = [uint32]0x00000002 # ADD_LINK on OUTBOUND_TRANSPORT_V4 only
    OutboundTransportV6 = [uint32]0x00000002 # ADD_LINK on OUTBOUND_TRANSPORT_V6 only
    FilterContainer = [uint32]0x00000001 # ADD only; no inheritance to filters
}

try {
    if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) {
        throw "The dedicated WFP ACL probe executable is missing: $AgentPath"
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "A service named $serviceName already exists on the disposable CI runner."
    }

    New-Item -ItemType Directory -Path $probeRoot -Force | Out-Null
    Copy-Item -LiteralPath $AgentPath -Destination $probeExe -Force
    New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue

    $binaryPath = '"' + $probeExe + '"'
    New-Service -Name $serviceName -DisplayName "blacklist-inevitable WFP ACL probe" -BinaryPathName $binaryPath -StartupType Manual -ErrorAction Stop | Out-Null
    $serviceCreated = $true
    $serviceConfiguration = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $serviceConfiguration -or $serviceConfiguration.StartName -ne "LocalSystem") {
        throw "The temporary WFP probe service was not registered as LocalSystem."
    }

    $account = [System.Security.Principal.NTAccount]::new("NT SERVICE\$serviceName")
    $serviceSid = $account.Translate([System.Security.Principal.SecurityIdentifier])
    $sidText = $serviceSid.Value
    Set-Content -LiteralPath $serviceSidPath -Value $sidText -NoNewline -Encoding ascii

    # Mirror the Agent executable and ProgramData report access on this disposable runner.
    $programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
    Invoke-Icacls @($programFilesRoot, "/grant", ("*" + $sidText + ":(RX)"), "/C")
    Invoke-Icacls @($probeRoot, "/grant", ("*" + $sidText + ":(OI)(CI)(RX)"), "/T", "/C")
    Invoke-Icacls @($stateRoot, "/grant", ("*" + $sidText + ":(OI)(CI)(RX)"), "/T", "/C")
    Invoke-Icacls @($reportDirectory, "/grant", ("*" + $sidText + ":(OI)(CI)(M)"), "/T", "/C")

    $sidTypeOutput = & (Join-Path $env:WINDIR "System32\sc.exe") sidtype $serviceName restricted 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not configure SERVICE_SID_TYPE_RESTRICTED: $($sidTypeOutput -join ' ')"
    }
    $queryOutput = & (Join-Path $env:WINDIR "System32\sc.exe") qsidtype $serviceName 2>&1
    if ($LASTEXITCODE -ne 0 -or (($queryOutput -join [Environment]::NewLine) -notmatch "RESTRICTED")) {
        throw "SCM did not confirm SERVICE_SID_TYPE_RESTRICTED: $($queryOutput -join ' ')"
    }

    # The preceding administrator-run live-BFE smoke test creates and validates
    # our persistent provider/sublayer. Snapshot every existing descriptor before
    # mutating any ACL, then grant only at the exact object/container check sites.
    $targets = @("Engine", "Provider", "Sublayer", "LayerV4", "LayerV6", "OutboundTransportV4", "OutboundTransportV6", "FilterContainer")
    foreach ($target in $targets) {
        $originalDacls[$target] = [BlacklistInevitable.WfpScopedAclInterop]::CaptureDaclBase64($target)
        if ([string]::IsNullOrWhiteSpace($originalDacls[$target])) {
            throw "Could not capture the original $target WFP DACL."
        }
    }

    $aclMutationAttempted = $true
    $wfpAclHelperPath = Join-Path $PSScriptRoot "windows-agent-wfp-acl.ps1"
    if (-not (Test-Path -LiteralPath $wfpAclHelperPath -PathType Leaf)) {
        throw "The shared Agent WFP ACL provisioner is missing: $wfpAclHelperPath"
    }
    & $wfpAclHelperPath -Action Provision -ServiceSid $sidText | Out-Null
    foreach ($entry in $aclRights.GetEnumerator()) {
        Write-Host ("Provisioned scoped WFP right 0x{0:X8} on {1}." -f [uint32]$entry.Value, $entry.Key)
    }

    Start-Service -Name $serviceName -ErrorAction Stop
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $reportPath -PathType Leaf) { break }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        $serviceQuery = & (Join-Path $env:WINDIR "System32\sc.exe") query $serviceName 2>&1
        throw "The restricted Agent service did not produce its WFP ACL report. Service state: $($serviceQuery -join ' ')"
    }

    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($report.schema_version -ne 2 -or
        $report.service_name -ne $serviceName -or
        $report.service_sid_type -ne "RESTRICTED" -or
        $report.outcome -ne "access_granted" -or
        $report.installed_filter_count -ne 12 -or
        $report.removed_filter_count -ne 12 -or
        $report.already_absent_filter_count -ne 12 -or
        $report.runtime_ids_checkpointed -ne $true -or
        $report.journal_removed -ne $true -or
        $report.synthetic_filters_committed_during_test -ne $true -or
        $report.synthetic_filters_may_remain -ne $false) {
        throw "The restricted-SID journaled WFP recovery acceptance test failed. Report: $($report | ConvertTo-Json -Depth 8 -Compress)"
    }

    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $artifactPath -Encoding utf8
    Write-Host "Restricted service SID: $sidText"
    Write-Host "WFP access result: $($report.outcome)"
    Write-Host "Route-bound synthetic filters committed across two interfaces: $($report.installed_filter_count)"
    Write-Host "Synthetic filters removed and verified absent: $($report.removed_filter_count)"
    Write-Host "Idempotent already-absent confirmations: $($report.already_absent_filter_count)"
    Write-Host "Runtime IDs persisted in recovery journal: $($report.runtime_ids_checkpointed)"
    Write-Host "Recovery journal removed after verified cleanup: $($report.journal_removed)"
    Write-Host "No synthetic filters remain on the disposable runner."
}
finally {
    $restoreErrors = [System.Collections.Generic.List[string]]::new()
    if ($aclMutationAttempted -and -not [string]::IsNullOrWhiteSpace($sidText)) {
        try {
            & (Join-Path $PSScriptRoot "windows-agent-wfp-acl.ps1") -Action Remove -ServiceSid $sidText | Out-Null
            Write-Host "Shared Agent WFP ACL provisioner removed its eight service SID grants."
        }
        catch {
            $restoreErrors.Add("Shared WFP ACL helper removal: $($_.Exception.Message)")
        }
    }

    if ($serviceCreated) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & (Join-Path $env:WINDIR "System32\sc.exe") delete $serviceName 2>&1 | Out-Null
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while ([DateTime]::UtcNow -lt $deadline) {
            if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 250
        }
    }

    if ($aclMutationAttempted) {
        # Restore in reverse scope order, continue after individual failures,
        # then independently compare each restored DACL with its saved bytes.
        $restoreOrder = @("FilterContainer", "OutboundTransportV6", "OutboundTransportV4", "LayerV6", "LayerV4", "Sublayer", "Provider", "Engine")
        foreach ($target in $restoreOrder) {
            try {
                [BlacklistInevitable.WfpScopedAclInterop]::RestoreDaclBase64($target, $originalDacls[$target])
                $restored = [BlacklistInevitable.WfpScopedAclInterop]::CaptureDaclBase64($target)
                if ($restored -ne $originalDacls[$target]) {
                    throw "The original $target WFP DACL was not restored byte-for-byte."
                }
                Write-Host "Original $target WFP DACL restored and verified byte-for-byte."
            }
            catch {
                $restoreErrors.Add("$target restoration: $($_.Exception.Message)")
            }
        }
    }

    Remove-Item -LiteralPath $serviceSidPath -Force -ErrorAction SilentlyContinue
    if ($restoreErrors.Count -gt 0) {
        throw ("WFP ACL restoration failed: " + ($restoreErrors -join "; "))
    }
}
