param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("PrepareUpgrade", "Install", "Uninstall")]
    [string] $Mode,
    [Parameter(Mandatory = $true)]
    [string] $AgentPath,
    [string] $DesktopPath,
    [string] $LogPath
)
$ErrorActionPreference = "Stop"
$ServiceName = "BlacklistInevitableAgent"
$DisplayName = "Blacklist Inevitable Agent"
$JournalDirectory = Join-Path $env:ProgramData "BlacklistInevitable\Agent"
$ServiceDacl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;IU)"

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogPath = Join-Path $env:TEMP "BlacklistInevitableAgent-service.log"
}
$script:AgentServiceLogPath = $LogPath
function Write-AgentServiceLog([string] $Message) {
    try {
        Add-Content -LiteralPath $script:AgentServiceLogPath -Value ("{0:o} {1}" -f [DateTime]::UtcNow, $Message) -Encoding UTF8
    } catch {
        # Diagnostics must never change the service security decision.
    }
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Agent service installation requires an elevated administrator token."
    }
}
function Get-NormalizedPath([string] $Path) {
    return [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}
function Get-ServiceRecord {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
}
function Get-RegisteredBinaryPath($Service) {
    if ($Service.PathName -match '^\s*"([^"]+)"') {
        return Get-NormalizedPath $Matches[1]
    }
    return Get-NormalizedPath (($Service.PathName -split '\s+', 2)[0])
}
function Assert-OwnedService($Service) {
    if (-not [string]::Equals((Get-RegisteredBinaryPath $Service), (Get-NormalizedPath $AgentPath), [StringComparison]::OrdinalIgnoreCase)) {
        throw "A service named $ServiceName already exists but points to a different executable. Refusing to modify or remove it."
    }
    if ($Service.StartName -notin @("LocalSystem", "NT AUTHORITY\SYSTEM")) {
        throw "The existing $ServiceName service is not running as LocalSystem."
    }
}
function Invoke-Sc([string[]] $Arguments) {
    Write-AgentServiceLog "SC BEGIN: $($Arguments -join ' ')"
    $output = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    foreach ($line in $output) { Write-AgentServiceLog "SC OUTPUT: $line" }
    Write-AgentServiceLog "SC END: exit=$exitCode"
    if ($exitCode -ne 0) {
        throw "sc.exe $($Arguments -join ' ') failed with exit code $exitCode."
    }
}
function Wait-ServiceState([string] $DesiredState, [int] $TimeoutSeconds = 30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $service = Get-ServiceRecord
        if (-not $service -and $DesiredState -eq "Absent") { return }
        if ($service -and $service.State -eq $DesiredState) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $actual = Get-ServiceRecord
    if ($actual) { throw "Timed out waiting for $ServiceName to become $DesiredState (current state: $($actual.State))." }
    if ($DesiredState -ne "Absent") { throw "Timed out waiting for $ServiceName to become $DesiredState." }
}
function Stop-OwnedService {
    $service = Get-ServiceRecord
    if (-not $service) { return }
    Assert-OwnedService $service
    if ($service.State -ne "Stopped") {
        try { Invoke-Sc @("stop", $ServiceName) }
        catch {
            $latest = Get-ServiceRecord
            if (-not $latest -or $latest.State -ne "Stopped") { throw }
        }
        Wait-ServiceState "Stopped"
    }
}
function Test-TrustedPublisherPair {
    Write-AgentServiceLog "Checking Agent and desktop Authenticode signatures."
    if ([string]::IsNullOrWhiteSpace($DesktopPath)) { throw "DesktopPath is required." }
    if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) { throw "The Agent executable is missing: $AgentPath" }
    if (-not (Test-Path -LiteralPath $DesktopPath -PathType Leaf)) { throw "The desktop executable is missing: $DesktopPath" }
    $agentSignature = Get-AuthenticodeSignature -LiteralPath $AgentPath
    $desktopSignature = Get-AuthenticodeSignature -LiteralPath $DesktopPath
    Write-AgentServiceLog "Signature status: Agent=$($agentSignature.Status); Desktop=$($desktopSignature.Status)"
    if ($agentSignature.Status -eq "NotSigned" -and $desktopSignature.Status -eq "NotSigned") { return $false }
    if ($agentSignature.Status -ne "Valid" -or $desktopSignature.Status -ne "Valid") {
        throw "Both binaries must have valid Authenticode signatures before a privileged service can be installed."
    }
    if (-not $agentSignature.SignerCertificate -or -not $desktopSignature.SignerCertificate) {
        throw "The signed binaries did not expose an Authenticode signer certificate."
    }
    if (-not [string]::Equals($agentSignature.SignerCertificate.Thumbprint, $desktopSignature.SignerCertificate.Thumbprint, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The Agent and desktop binaries are signed by different publishers."
    }
    return $true
}
function Set-ProtectedDirectoryAcl([string] $Path, [string[]] $AllowedSids) {
    Write-AgentServiceLog "Applying protected ACL to $Path; allowed SIDs=$($AllowedSids -join ',')"
    [void][IO.Directory]::CreateDirectory($Path)
    $directory = Get-Item -LiteralPath $Path -Force
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to use a reparse point for protected Agent data: $Path"
    }

    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($existingRule)
    }

    $adminSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl.SetOwner($adminSid)
    foreach ($sidText in $AllowedSids) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    Write-AgentServiceLog "ACL written: $Path"

    $verified = Get-Acl -LiteralPath $Path
    if (-not $verified.AreAccessRulesProtected) {
        throw "The protected Agent directory is still inheriting permissions: $Path"
    }
    $actualSids = @($verified.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $expectedSids = @($AllowedSids | Sort-Object -Unique)
    if (Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids) {
        throw "The protected Agent directory ACL contains an unexpected or missing principal: $Path"
    }
    if (@($verified.Access | Where-Object { $_.AccessControlType -ne "Allow" -or $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl }).Count -ne 0) {
        throw "The protected Agent directory ACL contains a non-full-control or deny entry: $Path"
    }
    if ($verified.Owner.Translate([Security.Principal.SecurityIdentifier]).Value -ne $adminSid.Value) {
        throw "The protected Agent directory owner is not BUILTIN\\Administrators: $Path"
    }
}

function Set-JournalDirectoryAcl([string] $ServiceSid) {
    $parentDirectory = Split-Path -Parent $JournalDirectory
    Set-ProtectedDirectoryAcl $parentDirectory @("S-1-5-18", "S-1-5-32-544")
    Set-ProtectedDirectoryAcl $JournalDirectory @("S-1-5-18", "S-1-5-32-544", $ServiceSid)
}

function Install-AgentService {
    Write-AgentServiceLog "Install-AgentService entered."
    $trusted = Test-TrustedPublisherPair
    $service = Get-ServiceRecord
    if (-not $trusted) {
        if ($service) {
            Stop-OwnedService
            Invoke-Sc @("config", $ServiceName, "start=", "disabled")
            Write-Warning "Unsigned package: the existing Agent service was stopped and disabled."
        } else {
            Write-Warning "Unsigned package: the desktop app will install without registering a privileged Agent service."
        }
        return 10
    }

    Write-AgentServiceLog "Trusted signer pair accepted; configuring service image path."
    $quotedAgentPath = '"' + (Get-NormalizedPath $AgentPath) + '"'
    if ($service) {
        Stop-OwnedService
        Invoke-Sc @("config", $ServiceName, "binPath=", $quotedAgentPath, "start=", "auto", "obj=", "LocalSystem", "type=", "own", "error=", "normal", "DisplayName=", $DisplayName)
    } else {
        Invoke-Sc @("create", $ServiceName, "binPath=", $quotedAgentPath, "start=", "auto", "obj=", "LocalSystem", "type=", "own", "error=", "normal", "DisplayName=", $DisplayName)
    }

    Invoke-Sc @("description", $ServiceName, "Authenticated local status IPC host. Network-changing operations are disabled.")
    Invoke-Sc @("sidtype", $ServiceName, "unrestricted")
    $sidOutput = (& "$env:SystemRoot\System32\sc.exe" showsid $ServiceName 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "sc.exe showsid failed for $ServiceName." }
    $sidMatch = [Regex]::Match($sidOutput, "S-1-5-80-(?:\d+-){4}\d+")
    if (-not $sidMatch.Success) { throw "Windows did not return a valid service SID for $ServiceName." }
    Write-AgentServiceLog "Service SID: $($sidMatch.Value); provisioning journal ACL."
    Set-JournalDirectoryAcl $sidMatch.Value
    Write-AgentServiceLog "Journal ACL provisioning complete."
    Invoke-Sc @("sdset", $ServiceName, $ServiceDacl)
    Write-AgentServiceLog "Service DACL applied; validating SCM record."

    $current = Get-ServiceRecord
    if (-not $current -or $current.StartName -notin @("LocalSystem", "NT AUTHORITY\SYSTEM")) {
        throw "The Agent service is not configured to run as LocalSystem."
    }
    if (-not [string]::Equals((Get-RegisteredBinaryPath $current), (Get-NormalizedPath $AgentPath), [StringComparison]::OrdinalIgnoreCase)) {
        throw "The Agent service image path did not match the installed binary."
    }
    Write-AgentServiceLog "Service configuration validated; starting service."
    Invoke-Sc @("start", $ServiceName)
    Wait-ServiceState "Running"
    Write-AgentServiceLog "Agent service reached RUNNING."
    return 0
}
function Remove-AgentService {
    $service = Get-ServiceRecord
    if (-not $service) { return }
    Stop-OwnedService
    Invoke-Sc @("delete", $ServiceName)
    Wait-ServiceState "Absent"
    # Keep ProgramData so future recovery metadata is not deleted by uninstall.
}
function Disable-AgentServiceAfterFailure {
    $service = Get-ServiceRecord
    if (-not $service) { return }
    try {
        Assert-OwnedService $service
    } catch {
        Write-Warning "Refusing rollback changes because the existing service is not owned by this installation: $_"
        return
    }
    try {
        Stop-OwnedService
    } catch {
        Write-Warning "The Agent service did not stop cleanly during rollback: $_"
    }
    try {
        Invoke-Sc @("config", $ServiceName, "start=", "disabled")
    } catch {
        Write-Warning "The Agent service could not be disabled during rollback: $_"
    }
}

function Prepare-AgentUpgrade {
    Write-AgentServiceLog "Prepare-AgentUpgrade entered."
    $service = Get-ServiceRecord
    if ($service) {
        Stop-OwnedService
        # Keep the service disabled throughout file replacement. A failed or
        # interrupted upgrade must never auto-start a partially replaced binary.
        Invoke-Sc @("config", $ServiceName, "start=", "disabled")
    }
    Write-AgentServiceLog "Prepare-AgentUpgrade complete."
}

try {
    Write-AgentServiceLog "START mode=$Mode identity=$([Security.Principal.WindowsIdentity]::GetCurrent().Name) AgentPath=$AgentPath DesktopPath=$DesktopPath"
    Assert-Elevated
    Write-AgentServiceLog "Elevated administrator token verified."
    $AgentPath = Get-NormalizedPath $AgentPath
    switch ($Mode) {
        "PrepareUpgrade" { Prepare-AgentUpgrade; Write-AgentServiceLog "EXIT mode=$Mode code=0"; exit 0 }
        "Install" {
            if ([string]::IsNullOrWhiteSpace($DesktopPath)) { throw "DesktopPath is required for Agent service installation." }
            $DesktopPath = Get-NormalizedPath $DesktopPath
            $installResult = Install-AgentService
            Write-AgentServiceLog "EXIT mode=$Mode code=$installResult"
            exit $installResult
        }
        "Uninstall" { Remove-AgentService; Write-AgentServiceLog "EXIT mode=$Mode code=0"; exit 0 }
    }
} catch {
    Write-AgentServiceLog "ERROR mode=${Mode}: $($_.Exception.Message)"
    Write-AgentServiceLog "ERROR SCRIPT: $($_.ScriptStackTrace)"
    if ($Mode -eq "Install") {
        Disable-AgentServiceAfterFailure
    }
    Write-Error $_
    Write-AgentServiceLog "EXIT mode=$Mode code=1"
    exit 1
}
