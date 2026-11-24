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
$artifactPath = Join-Path $env:RUNNER_TEMP "wfp-service-sid-probe.json"
$serviceCreated = $false
$aclMutationAttempted = $false
$originalEngineDacl = $null

# This helper runs only on the disposable, elevated GitHub-hosted Windows runner.
# It captures the complete BFE Engine DACL, grants one service SID only the
# WFP-specific rights needed by the rollback-only probe, and restores the
# original DACL byte-for-byte in finally.
if (-not ("BlacklistInevitable.WfpEngineAclInterop" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace BlacklistInevitable {
    public static class WfpEngineAclInterop {
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const uint RPC_C_AUTHN_WINNT = 10;

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
            uint securityInfo, IntPtr sidOwner, IntPtr sidGroup,
            IntPtr dacl, IntPtr sacl);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern void FwpmFreeMemory0(ref IntPtr pointer);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern uint SetEntriesInAclW(uint count,
            ref ExplicitAccessW entries, IntPtr oldAcl, out IntPtr newAcl);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        private static IntPtr OpenEngine() {
            IntPtr engine;
            uint status = FwpmEngineOpen0(IntPtr.Zero, RPC_C_AUTHN_WINNT,
                IntPtr.Zero, IntPtr.Zero, out engine);
            if (status != 0 || engine == IntPtr.Zero)
                throw new InvalidOperationException(
                    "FwpmEngineOpen0 for ACL provisioning failed: 0x" + status.ToString("X8"));
            return engine;
        }

        private static byte[] ReadDacl(IntPtr engine) {
            IntPtr owner, group, dacl, sacl, descriptor;
            uint status = FwpmEngineGetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                out owner, out group, out dacl, out sacl, out descriptor);
            if (status != 0 || descriptor == IntPtr.Zero)
                throw new InvalidOperationException(
                    "FwpmEngineGetSecurityInfo0 failed: 0x" + status.ToString("X8"));
            try {
                // A NULL DACL grants unrestricted access. Refuse to replace it.
                if (dacl == IntPtr.Zero)
                    throw new InvalidOperationException("The BFE Engine has a NULL DACL; refusing ACL mutation.");
                int size = unchecked((ushort)Marshal.ReadInt16(IntPtr.Add(dacl, 2)));
                if (size < 8)
                    throw new InvalidOperationException("The BFE Engine DACL has an invalid ACL size.");
                byte[] bytes = new byte[size];
                Marshal.Copy(dacl, bytes, 0, size);
                return bytes;
            }
            finally {
                FwpmFreeMemory0(ref descriptor);
            }
        }

        public static string CaptureEngineDaclBase64() {
            IntPtr engine = OpenEngine();
            try { return Convert.ToBase64String(ReadDacl(engine)); }
            finally { FwpmEngineClose0(engine); }
        }

        public static void AddTemporaryServiceAce(string serviceSid, uint accessMask) {
            IntPtr engine = OpenEngine();
            IntPtr descriptor = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            IntPtr newAcl = IntPtr.Zero;
            try {
                IntPtr owner, group, dacl, sacl;
                uint readStatus = FwpmEngineGetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                    out owner, out group, out dacl, out sacl, out descriptor);
                if (readStatus != 0 || descriptor == IntPtr.Zero)
                    throw new InvalidOperationException(
                        "FwpmEngineGetSecurityInfo0 before grant failed: 0x" + readStatus.ToString("X8"));
                if (dacl == IntPtr.Zero)
                    throw new InvalidOperationException("The BFE Engine has a NULL DACL; refusing ACL mutation.");
                if (!ConvertStringSidToSidW(serviceSid, out sid))
                    throw new InvalidOperationException(
                        "ConvertStringSidToSidW failed: " + Marshal.GetLastWin32Error());

                ExplicitAccessW entry = new ExplicitAccessW();
                entry.grfAccessPermissions = accessMask;
                entry.grfAccessMode = 1; // GRANT_ACCESS
                entry.grfInheritance = 3; // CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE; cascade through WFP containers and objects.
                entry.Trustee = new TrusteeW {
                    pMultipleTrustee = IntPtr.Zero,
                    MultipleTrusteeOperation = 0, // NO_MULTIPLE_TRUSTEE
                    TrusteeForm = 0, // TRUSTEE_IS_SID
                    TrusteeType = 1, // TRUSTEE_IS_USER
                    ptstrName = sid
                };

                uint aclStatus = SetEntriesInAclW(1, ref entry, dacl, out newAcl);
                if (aclStatus != 0 || newAcl == IntPtr.Zero)
                    throw new InvalidOperationException(
                        "SetEntriesInAclW failed: 0x" + aclStatus.ToString("X8"));

                uint setStatus = FwpmEngineSetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                    IntPtr.Zero, IntPtr.Zero, newAcl, IntPtr.Zero);
                if (setStatus != 0)
                    throw new InvalidOperationException(
                        "FwpmEngineSetSecurityInfo0 granting the temporary probe ACE failed: 0x" +
                        setStatus.ToString("X8"));
            }
            finally {
                if (newAcl != IntPtr.Zero) LocalFree(newAcl);
                if (sid != IntPtr.Zero) LocalFree(sid);
                if (descriptor != IntPtr.Zero) FwpmFreeMemory0(ref descriptor);
                FwpmEngineClose0(engine);
            }
        }

        public static void RestoreEngineDaclBase64(string base64Dacl) {
            byte[] bytes = Convert.FromBase64String(base64Dacl);
            if (bytes.Length < 8)
                throw new InvalidOperationException("The captured BFE Engine DACL is invalid.");
            IntPtr acl = Marshal.AllocHGlobal(bytes.Length);
            IntPtr engine = IntPtr.Zero;
            try {
                Marshal.Copy(bytes, 0, acl, bytes.Length);
                engine = OpenEngine();
                uint status = FwpmEngineSetSecurityInfo0(engine, DACL_SECURITY_INFORMATION,
                    IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                if (status != 0)
                    throw new InvalidOperationException(
                        "FwpmEngineSetSecurityInfo0 restoring the original DACL failed: 0x" +
                        status.ToString("X8"));
            }
            finally {
                if (engine != IntPtr.Zero) FwpmEngineClose0(engine);
                Marshal.FreeHGlobal(acl);
            }
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

    # Mirror the service's narrow filesystem access needed to load the probe
    # and write its diagnostic report. All changes are on the disposable runner.
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

    # Exact minimum for this code path: WFP ADD, ADD_LINK, BEGIN_WRITE_TXN,
    # READ and standard DELETE. OPEN already succeeds through BFE's default
    # Everyone ACE. No generic WRITE/ALL or BEGIN_READ_TXN is granted.
    $minimumWfpRights = [uint32]0x0001008B
    $originalEngineDacl = [BlacklistInevitable.WfpEngineAclInterop]::CaptureEngineDaclBase64()
    if ([string]::IsNullOrWhiteSpace($originalEngineDacl)) {
        throw "Could not capture the original BFE Engine DACL."
    }
    $aclMutationAttempted = $true
    [BlacklistInevitable.WfpEngineAclInterop]::AddTemporaryServiceAce($sidText, $minimumWfpRights)

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
    if ($report.schema_version -ne 1 -or
        $report.service_name -ne $serviceName -or
        $report.service_sid_type -ne "RESTRICTED" -or
        $report.traffic_filters_committed -ne $false -or
        $report.outcome -ne "access_granted" -or
        $report.validated_filter_count -lt 1 -or
        $report.rolled_back_filter_count -ne $report.validated_filter_count) {
        throw "The restricted Agent WFP ACL acceptance test failed. Report: $($report | ConvertTo-Json -Depth 8 -Compress)"
    }

    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $artifactPath -Encoding utf8
    Write-Host "Restricted service SID: $sidText"
    Write-Host "WFP rights granted temporarily: 0x$($minimumWfpRights.ToString('X8'))"
    Write-Host "WFP access result: $($report.outcome)"
    Write-Host "Validated filters: $($report.validated_filter_count)"
    Write-Host "Rolled-back filters: $($report.rolled_back_filter_count)"
    Write-Host "No traffic filter was committed."
}
finally {
    if ($serviceCreated) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & (Join-Path $env:WINDIR "System32\sc.exe") delete $serviceName 2>&1 | Out-Null
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while ([DateTime]::UtcNow -lt $deadline) {
            if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 250
        }
    }

    if ($aclMutationAttempted -and -not [string]::IsNullOrWhiteSpace($originalEngineDacl)) {
        [BlacklistInevitable.WfpEngineAclInterop]::RestoreEngineDaclBase64($originalEngineDacl)
        $restoredEngineDacl = [BlacklistInevitable.WfpEngineAclInterop]::CaptureEngineDaclBase64()
        if ($restoredEngineDacl -ne $originalEngineDacl) {
            throw "The original BFE Engine DACL was not restored byte-for-byte after the disposable probe."
        }
        Write-Host "Original BFE Engine DACL restored and verified byte-for-byte."
    }
}
