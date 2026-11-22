$ErrorActionPreference = "Stop"

$agentServiceLog = Join-Path $env:TEMP "BlacklistInevitableAgent-service.log"
$installerLog = Join-Path $env:TEMP "blacklist-inevitable-nsis-install.log"
$uninstallerLog = Join-Path $env:TEMP "blacklist-inevitable-nsis-uninstall.log"
$uninstallHookLog = Join-Path $env:TEMP "BlacklistInevitableAgent-uninstall-hook.log"
$agentIpcDiagnostic = Join-Path $env:ProgramData "BlacklistInevitable\Agent\last-ipc-error.txt"
Remove-Item -LiteralPath $agentServiceLog -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $installerLog -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $uninstallerLog -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $uninstallHookLog -Force -ErrorAction SilentlyContinue

$installerDirectory = Join-Path $PSScriptRoot "..\src-tauri\target\release\bundle\nsis"
$installer = Get-ChildItem -Path $installerDirectory -Filter "*.exe" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $installer) {
    throw "No NSIS installer was found in $installerDirectory"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Installer smoke-test identity: $($identity.Name); elevated administrator token: $isElevated"
if (-not $isElevated) {
    throw "The Windows installer smoke test is not running with an elevated administrator token. A per-machine NSIS installer would wait for an unavailable UAC prompt."
}

Write-Host "Installing $($installer.Name) silently..."
$installProcess = Start-Process -FilePath $installer.FullName -ArgumentList @("/S", "/LOG=$installerLog") -PassThru
if (-not $installProcess.WaitForExit(180000)) {
    $installProcess.Refresh()
    $installerPid = $installProcess.Id
    $childProcesses = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -eq $installerPid -or $_.ParentProcessId -eq $installerPid } |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine)
    $serviceSnapshot = Get-Service -Name "BlacklistInevitableAgent" -ErrorAction SilentlyContinue
    $serviceRecordSnapshot = Get-CimInstance -ClassName Win32_Service -Filter "Name='BlacklistInevitableAgent'" -ErrorAction SilentlyContinue
    $installerWindow = Get-Process -Id $installerPid -ErrorAction SilentlyContinue |
        Select-Object Id, MainWindowHandle, MainWindowTitle, Responding, StartTime
    Write-Host "Installer PID $installerPid did not exit within 180 seconds."
    Write-Host ("Installer window snapshot: " + ($installerWindow | Format-List | Out-String))
    Write-Host "Agent service snapshot: $(if ($serviceSnapshot) { $serviceSnapshot.Status } else { 'not registered' })"
    if ($serviceRecordSnapshot) {
        Write-Host "Agent service details: State=$($serviceRecordSnapshot.State); StartName=$($serviceRecordSnapshot.StartName); PathName=$($serviceRecordSnapshot.PathName)"
    }
    Write-Host ("Installer process tree snapshot: " + ($childProcesses | Format-Table -AutoSize | Out-String))
    if (Test-Path -LiteralPath $agentServiceLog) {
        Write-Host "Agent helper diagnostic log:"
        Get-Content -LiteralPath $agentServiceLog -Tail 200 | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "Agent helper diagnostic log was not created; installer may have stalled before invoking the PowerShell helper."
    }
    try {
        $installProcess.Kill($true)
        [void]$installProcess.WaitForExit(10000)
    } catch {
        Write-Warning "Could not terminate the timed-out installer process tree: $_"
    }
    throw "The NSIS installer did not exit within 180 seconds. The process and service snapshots above identify where installation stalled."
}
$installProcess.Refresh()
if ($installProcess.ExitCode -ne 0) {
    if (Test-Path -LiteralPath $installerLog) {
        Write-Host "NSIS installer diagnostic log:"
        Get-Content -LiteralPath $installerLog -Tail 250 | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "NSIS installer log was not created: $installerLog"
    }
    if (Test-Path -LiteralPath $agentServiceLog) {
        Write-Host "Agent helper diagnostic log:"
        Get-Content -LiteralPath $agentServiceLog -Tail 200 | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "Agent helper diagnostic log was not created; the failure occurred before the helper wrote its first entry."
    }
    throw "The NSIS installer exited with code $($installProcess.ExitCode)."
}

$uninstallRoots = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
)
$entries = @()
foreach ($root in $uninstallRoots) {
    $entries += Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName -eq "blacklist-inevitable" }
}
$entry = $entries | Select-Object -First 1

if (-not $entry -or -not $entry.UninstallString) {
    throw "The installer did not register an uninstall entry for blacklist-inevitable."
}

if ($entry.UninstallString -match '^"([^"]+)"') {
    $uninstallerPath = $Matches[1]
} else {
    $uninstallerPath = ($entry.UninstallString -split '\s+', 2)[0]
}

if (-not (Test-Path -LiteralPath $uninstallerPath -PathType Leaf)) {
    throw "The registered uninstaller was not found: $uninstallerPath"
}

$installDirectory = Split-Path -Parent $uninstallerPath
$appPath = Join-Path $installDirectory "blacklist-inevitable.exe"
$agentPath = Join-Path $installDirectory "blacklist-inevitable-agent.exe"
if (-not (Test-Path -LiteralPath $appPath -PathType Leaf)) {
    throw "The installed application executable was not found: $appPath"
}
if (-not (Test-Path -LiteralPath $agentPath -PathType Leaf)) {
    throw "The Agent service sidecar was not installed next to the desktop application: $agentPath"
}

$agentSignature = Get-AuthenticodeSignature -LiteralPath $agentPath
$desktopSignature = Get-AuthenticodeSignature -LiteralPath $appPath
$service = Get-Service -Name "BlacklistInevitableAgent" -ErrorAction SilentlyContinue
if ($agentSignature.Status -eq "Valid" -and $desktopSignature.Status -eq "Valid" -and
    $agentSignature.SignerCertificate.Thumbprint -eq $desktopSignature.SignerCertificate.Thumbprint) {
    if (-not $service -or $service.Status -ne "Running") {
        throw "The trusted signed package did not install and start the LocalSystem Agent service."
    }
    $serviceRecord = Get-CimInstance -ClassName Win32_Service -Filter "Name='BlacklistInevitableAgent'"
    if ($serviceRecord.StartName -notin @("LocalSystem", "NT AUTHORITY\SYSTEM")) {
        throw "The Agent service is not running as LocalSystem."
    }
    if ($serviceRecord.StartMode -ne "Auto") {
        throw "The Agent service is not configured for automatic startup."
    }
    $expectedServiceImagePath = '"' + [IO.Path]::GetFullPath($agentPath) + '"'
    if (-not [string]::Equals(([string]$serviceRecord.PathName).Trim(), $expectedServiceImagePath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The Agent service image path is not exactly the quoted installed sidecar path: [$($serviceRecord.PathName)]"
    }
    $sidOutput = (& "$env:SystemRoot\System32\sc.exe" showsid "BlacklistInevitableAgent" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Could not query the Agent service SID." }
    $sidMatch = [Regex]::Match($sidOutput, "S-1-5-80-(?:\d+-){4}\d+")
    if (-not $sidMatch.Success) { throw "The Agent service SID was not provisioned." }
    $sidTypeOutput = (& "$env:SystemRoot\System32\sc.exe" qsidtype "BlacklistInevitableAgent" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $sidTypeOutput -notmatch "UNRESTRICTED") {
        throw "The Agent service SID is not enabled."
    }
    $serviceSecurity = (& "$env:SystemRoot\System32\sc.exe" sdshow "BlacklistInevitableAgent" 2>&1 | Out-String)
    $sdshowExitCode = $LASTEXITCODE
    Write-Host "Agent service SDDL (sc.exe sdshow, exit=$sdshowExitCode): $($serviceSecurity.Trim())"
    if ($sdshowExitCode -ne 0) {
        throw "Could not read the Agent service DACL with sc.exe sdshow: $($serviceSecurity.Trim())"
    }

    # SCM may canonicalize generic SDDL rights (GA/LC) to their service-specific
    # access masks. Parse the descriptor and compare effective masks instead of
    # relying on the exact textual spelling returned by sdshow.
    try {
        $serviceDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($serviceSecurity.Trim())
    } catch {
        throw "Could not parse the Agent service SDDL [$($serviceSecurity.Trim())]: $($_.Exception.Message)"
    }
    $daclProtected = [bool]($serviceDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
    $actualServiceAces = @()
    foreach ($ace in $serviceDescriptor.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce] -or
            $ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) {
            throw "The Agent service DACL contains a non-standard or non-allow ACE: $($ace.GetType().FullName), type=$($ace.AceType)."
        }
        $actualServiceAces += [pscustomobject]@{
            Sid = $ace.SecurityIdentifier.Value
            Mask = [uint32]$ace.AccessMask
            Flags = $ace.AceFlags
        }
    }
    $expectedServiceMasks = @{
        "S-1-5-18" = @(0x000F01FF, 0x10000000) # LocalSystem: SERVICE_ALL_ACCESS
        "S-1-5-32-544" = @(0x000F01FF, 0x10000000) # Administrators: SERVICE_ALL_ACCESS
        "S-1-5-4" = @(0x00000004) # Interactive Users: SERVICE_QUERY_STATUS only
    }
    $serviceDaclValid = $daclProtected -and $actualServiceAces.Count -eq 3
    foreach ($sid in $expectedServiceMasks.Keys) {
        $sidAces = @($actualServiceAces | Where-Object { $_.Sid -eq $sid })
        if ($sidAces.Count -ne 1 -or
            $sidAces[0].Mask -notin $expectedServiceMasks[$sid] -or
            $sidAces[0].Flags -ne [System.Security.AccessControl.AceFlags]::None) {
            $serviceDaclValid = $false
        }
    }
    if (-not $serviceDaclValid) {
        $actualDescription = ($actualServiceAces | ForEach-Object {
            "{0}=0x{1:X8}/flags:{2}" -f $_.Sid, $_.Mask, $_.Flags
        }) -join "; "
        Write-Host "Agent service DACL parsed details: protected=$daclProtected; ACEs=$actualDescription"
        if (Test-Path -LiteralPath $agentServiceLog) {
            Write-Host "Agent helper diagnostic log:"
            Get-Content -LiteralPath $agentServiceLog -Tail 100 | ForEach-Object { Write-Host $_ }
        }
        throw "The Agent service DACL is not the exact protected policy. Expected SYSTEM and Administrators SERVICE_ALL_ACCESS (0xF01FF), Interactive Users SERVICE_QUERY_STATUS (0x4); actual: $actualDescription"
    }
    $journalDirectory = Join-Path $env:ProgramData "BlacklistInevitable\Agent"
    if (-not (Test-Path -LiteralPath $journalDirectory -PathType Container)) {
        throw "The protected Agent journal directory was not provisioned."
    }
    $journalAcl = Get-Acl -LiteralPath $journalDirectory
    if (-not $journalAcl.AreAccessRulesProtected) { throw "The Agent journal directory inherits permissions." }
    $journalRules = $journalAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $journalSids = @($journalRules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    $expectedJournalSids = @("S-1-5-18", "S-1-5-32-544", $sidMatch.Value) | Sort-Object -Unique
    if (Compare-Object -ReferenceObject $expectedJournalSids -DifferenceObject $journalSids) {
        throw "The Agent journal directory ACL is not restricted to SYSTEM, Administrators, and the Agent service SID."
    }

    # Clear a previous run's protected service-side diagnostic before probing IPC.
    Remove-Item -LiteralPath $agentIpcDiagnostic -Force -ErrorAction SilentlyContinue

    # Exercise the installed service's status-only named-pipe protocol before
    # launching the desktop app. This proves that the LocalSystem service is
    # accepting an authenticated local caller and returning a correlated frame.
    if (-not ("BlacklistInevitable.SmokeSessionProbe" -as [type])) {
        Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
namespace BlacklistInevitable {
    public static class SmokeSessionProbe {
        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern uint WTSGetActiveConsoleSessionId();
    }
}
"@
    }
    $clientSessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $consoleSessionId = [BlacklistInevitable.SmokeSessionProbe]::WTSGetActiveConsoleSessionId()
    Write-Host "Agent IPC smoke-test client session: $clientSessionId; active console session: $consoleSessionId"
    if ($clientSessionId -ne $consoleSessionId) {
        throw "The Windows smoke-test process is not running in the active console session; authenticated Agent IPC cannot be tested from this session."
    }

    $agentPipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        ".",
        "BlacklistInevitable.Agent.v1",
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None,
        [System.Security.Principal.TokenImpersonationLevel]::Identification
    )
    try {
        $agentPipe.Connect(10000)
        $statusJson = '{"version":1,"requestId":"ci-status-01","operation":"getStatus"}'
        $null = $statusJson | ConvertFrom-Json -ErrorAction Stop
        $statusRequest = [Text.Encoding]::UTF8.GetBytes($statusJson)
        $statusHeader = [BitConverter]::GetBytes([uint32]$statusRequest.Length)
        $agentPipe.Write($statusHeader, 0, $statusHeader.Length)
        $agentPipe.Write($statusRequest, 0, $statusRequest.Length)
        $agentPipe.Flush()

        $readExact = {
            param([IO.Stream]$Stream, [int]$Count)
            $buffer = New-Object byte[] $Count
            $offset = 0
            while ($offset -lt $Count) {
                $read = $Stream.Read($buffer, $offset, $Count - $offset)
                if ($read -le 0) { throw "The Agent pipe closed before a complete response frame arrived." }
                $offset += $read
            }
            return ,$buffer
        }
        $responseHeader = & $readExact $agentPipe 4
        $responseLength = [BitConverter]::ToUInt32($responseHeader, 0)
        if ($responseLength -lt 1 -or $responseLength -gt 131072) {
            throw "The Agent status response frame length is invalid: $responseLength."
        }
        $responsePayload = & $readExact $agentPipe ([int]$responseLength)
        $agentResponse = [Text.Encoding]::UTF8.GetString($responsePayload) | ConvertFrom-Json
        if ($agentResponse.version -ne 1 -or
            $agentResponse.requestId -ne "ci-status-01" -or
            $agentResponse.status -ne "ok") {
            throw "The Agent status response did not match the request or was not successful."
        }
        Write-Host "Verified Agent named-pipe status response and request correlation."
    }
    catch {
        Write-Host "Agent IPC request failed; collecting protected service-side diagnostics."
        if (Test-Path -LiteralPath $agentIpcDiagnostic -PathType Leaf) {
            Get-Content -LiteralPath $agentIpcDiagnostic -Tail 20 | ForEach-Object { Write-Host "AGENT IPC: $_" }
        } else {
            Write-Host "No service-side IPC diagnostic file was written."
        }
        $serviceAfterIpc = Get-Service -Name "BlacklistInevitableAgent" -ErrorAction SilentlyContinue
        $serviceRecordAfterIpc = Get-CimInstance -ClassName Win32_Service -Filter "Name='BlacklistInevitableAgent'" -ErrorAction SilentlyContinue
        Write-Host "Agent service after IPC failure: $(if ($serviceAfterIpc) { $serviceAfterIpc.Status } else { 'not registered' }); PID=$($serviceRecordAfterIpc.ProcessId); ExitCode=$($serviceRecordAfterIpc.ExitCode); ServiceSpecificExitCode=$($serviceRecordAfterIpc.ServiceSpecificExitCode)"
        $scSnapshot = (& "$env:SystemRoot\System32\sc.exe" queryex "BlacklistInevitableAgent" 2>&1 | Out-String)
        Write-Host "Agent service queryex snapshot: $($scSnapshot.Trim())"
        throw
    }
    finally {
        $agentPipe.Dispose()
    }
} elseif ($agentSignature.Status -eq "NotSigned" -and $desktopSignature.Status -eq "NotSigned") {
    if ($service) {
        throw "An unsigned package must not register a privileged Agent service."
    }
} else {
    throw "The installed Agent and desktop binaries do not have matching valid Authenticode signatures."
}

Write-Host "Launching the installed desktop application..."
$appProcess = Start-Process -FilePath $appPath -WorkingDirectory $installDirectory -PassThru
try {
    Start-Sleep -Seconds 6
    $appProcess.Refresh()
    if ($appProcess.HasExited) {
        throw "The desktop application exited during its startup smoke test (code: $($appProcess.ExitCode))."
    }
}
finally {
    if (-not $appProcess.HasExited) {
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $appProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
}

Write-Host "Uninstalling the application silently..."
# NSIS normally starts a second copy of its uninstaller from %TEMP% and exits
# the original process immediately. Copy it ourselves and pass _?=$INSTDIR so
# this process performs the uninstall directly and its exit code is meaningful.
# The copy must live outside $installDirectory so NSIS can delete the installed
# uninstall.exe and remove the installation directory.
$smokeUninstaller = Join-Path $env:RUNNER_TEMP "blacklist-inevitable-smoke-uninstaller.exe"
Remove-Item -LiteralPath $smokeUninstaller -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $uninstallerPath -Destination $smokeUninstaller -Force
if (-not (Test-Path -LiteralPath $smokeUninstaller -PathType Leaf)) {
    throw "Could not stage a temporary copy of the NSIS uninstaller."
}
$uninstallArguments = @("/S", "/LOG=$uninstallerLog", "_?=$installDirectory")
$uninstallProcess = Start-Process -FilePath $smokeUninstaller -ArgumentList $uninstallArguments -PassThru
if (-not $uninstallProcess.WaitForExit(120000)) {
    $uninstallPid = $uninstallProcess.Id
    $uninstallTree = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -eq $uninstallPid -or $_.ParentProcessId -eq $uninstallPid } |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine)
    Write-Host ("Uninstaller process tree snapshot: " + ($uninstallTree | Format-Table -AutoSize | Out-String))
    try {
        $uninstallProcess.Kill($true)
        [void]$uninstallProcess.WaitForExit(10000)
    } catch {
        Write-Warning "Could not terminate the timed-out uninstaller process tree: $_"
    }
    throw "The NSIS uninstaller did not finish within 120 seconds."
}
$uninstallProcess.Refresh()
if ($uninstallProcess.ExitCode -ne 0) {
    Write-Host "NSIS uninstaller exited with code $($uninstallProcess.ExitCode)."
    if (Test-Path -LiteralPath $uninstallerLog) {
        Write-Host "NSIS uninstaller diagnostic log:"
        Get-Content -LiteralPath $uninstallerLog -Tail 300 | ForEach-Object { Write-Host $_ }
    }
    if (Test-Path -LiteralPath $uninstallHookLog) {
        Write-Host "NSIS PREUNINSTALL hook diagnostic log:"
        Get-Content -LiteralPath $uninstallHookLog -Tail 100 | ForEach-Object { Write-Host $_ }
    }
    if (Test-Path -LiteralPath $agentServiceLog) {
        Write-Host "Agent helper diagnostic log:"
        Get-Content -LiteralPath $agentServiceLog -Tail 200 | ForEach-Object { Write-Host $_ }
    }
    throw "The NSIS uninstaller exited with code $($uninstallProcess.ExitCode)."
}
if (Test-Path -LiteralPath $appPath) {
    $remainingApp = Get-Item -LiteralPath $appPath -Force | Select-Object FullName, Length, LastWriteTime, Attributes
    $appProcesses = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -eq $appPath } |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
    Write-Host "Uninstaller exit code: $($uninstallProcess.ExitCode)"
    Write-Host ("Remaining application file: " + ($remainingApp | Format-List | Out-String))
    Write-Host ("Processes still using installed application path: " + ($appProcesses | Format-Table -AutoSize | Out-String))
    if (Test-Path -LiteralPath $uninstallerLog) {
        Write-Host "NSIS uninstaller diagnostic log:"
        Get-Content -LiteralPath $uninstallerLog -Tail 300 | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "NSIS uninstaller log was not created: $uninstallerLog"
    }
    if (Test-Path -LiteralPath $uninstallHookLog) {
        Write-Host "NSIS PREUNINSTALL hook diagnostic log:"
        Get-Content -LiteralPath $uninstallHookLog -Tail 100 | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "NSIS PREUNINSTALL hook was not entered; diagnostic log was not created: $uninstallHookLog"
    }
    $persistedHelper = Join-Path $installDirectory "agent-service.ps1"
    Write-Host "Persisted uninstall helper exists: $(Test-Path -LiteralPath $persistedHelper -PathType Leaf)"
    if (Test-Path -LiteralPath $agentServiceLog) {
        Write-Host "Agent helper diagnostic log:"
        Get-Content -LiteralPath $agentServiceLog -Tail 200 | ForEach-Object { Write-Host $_ }
    }
    throw "The application executable remains after uninstallation: $appPath"
}
if (Test-Path -LiteralPath $agentPath) {
    throw "The Agent sidecar remains after uninstallation: $agentPath"
}
if (Test-Path -LiteralPath $uninstallerPath) {
    throw "The installed NSIS uninstaller remains after uninstallation: $uninstallerPath"
}
if (Test-Path -LiteralPath (Join-Path $installDirectory "agent-service.ps1")) {
    throw "The persisted Agent service helper remains after uninstallation."
}
if (Test-Path -LiteralPath $installDirectory -PathType Container) {
    $remainingEntries = @(Get-ChildItem -LiteralPath $installDirectory -Force -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName)
    $remainingDescription = if ($remainingEntries.Count -gt 0) {
        $remainingEntries -join "; "
    } else {
        "(the directory is empty)"
    }
    throw "The installation directory remains after uninstallation: $installDirectory; contents: $remainingDescription"
}
if (Get-Service -Name "BlacklistInevitableAgent" -ErrorAction SilentlyContinue) {
    throw "The Agent Windows service remains registered after uninstallation."
}
Write-Host "Verified uninstall cleanup: desktop executable, Agent sidecar, uninstall helper, uninstaller, installation directory, and Agent service are all absent."


# Build real unsigned PE executables with the Rust toolchain already validated
# by this workflow. PowerShell 7's Add-Type does not support ConsoleApplication
# output, so do not use Add-Type -OutputType ConsoleApplication for this probe.
$unsignedProbeDirectory = Join-Path $env:RUNNER_TEMP "blacklist-inevitable-unsigned-agent-probe"
New-Item -ItemType Directory -Path $unsignedProbeDirectory -Force | Out-Null
try {
    $rustc = (Get-Command rustc -ErrorAction Stop).Source
    $unsignedProbeSource = Join-Path $unsignedProbeDirectory "unsigned-probe.rs"
    Set-Content -LiteralPath $unsignedProbeSource -Value "fn main() {}" -Encoding ascii
    $unsignedAgent = Join-Path $unsignedProbeDirectory "agent.exe"
    $unsignedDesktop = Join-Path $unsignedProbeDirectory "desktop.exe"

    & $rustc --edition=2021 --target x86_64-pc-windows-msvc --crate-name unsigned_agent_probe -o $unsignedAgent $unsignedProbeSource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $unsignedAgent -PathType Leaf)) {
        throw "Could not compile the unsigned Agent PE probe (rustc exit code: $LASTEXITCODE)."
    }
    & $rustc --edition=2021 --target x86_64-pc-windows-msvc --crate-name unsigned_desktop_probe -o $unsignedDesktop $unsignedProbeSource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $unsignedDesktop -PathType Leaf)) {
        throw "Could not compile the unsigned desktop PE probe (rustc exit code: $LASTEXITCODE)."
    }

    if ((Get-AuthenticodeSignature -LiteralPath $unsignedAgent).Status -ne "NotSigned" -or
        (Get-AuthenticodeSignature -LiteralPath $unsignedDesktop).Status -ne "NotSigned") {
        throw "The unsigned service-policy probe binaries unexpectedly have Authenticode signatures."
    }
    $serviceHelper = Join-Path $PSScriptRoot "..\\src-tauri\\windows\\agent-service.ps1"
    & "$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $serviceHelper -Mode Install -AgentPath $unsignedAgent -DesktopPath $unsignedDesktop
    if ($LASTEXITCODE -ne 10) {
        throw "The unsigned Agent installation policy returned $LASTEXITCODE instead of the explicit skip code 10."
    }
    if (Get-Service -Name "BlacklistInevitableAgent" -ErrorAction SilentlyContinue) {
        throw "The unsigned service-policy probe registered a privileged Windows service."
    }
} finally {
    Remove-Item -LiteralPath $unsignedProbeDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

# The unsigned-policy helper intentionally returns 10 to indicate that an unsigned
# package must skip privileged service registration. We asserted that exact code
# above; clear PowerShell's native exit status so the successful smoke test itself
# returns success to the GitHub Actions pwsh wrapper.
$global:LASTEXITCODE = 0

Write-Host "Windows installer smoke test passed: install, launch, named-pipe status IPC, signed service lifecycle, complete uninstall, and unsigned-package rejection."
