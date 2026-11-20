param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("PrepareUpgrade", "Install", "Uninstall")]
    [string] $Mode,
    [Parameter(Mandatory = $true)]
    [string] $AgentPath,
    [string] $DesktopPath
)
$ErrorActionPreference = "Stop"
$ServiceName = "BlacklistInevitableAgent"
$DisplayName = "Blacklist Inevitable Agent"
$JournalDirectory = Join-Path $env:ProgramData "BlacklistInevitable\Agent"
$ServiceDacl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;IU)"

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
    & "$env:SystemRoot\System32\sc.exe" @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
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
    if ([string]::IsNullOrWhiteSpace($DesktopPath)) { throw "DesktopPath is required." }
    if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) { throw "The Agent executable is missing: $AgentPath" }
    if (-not (Test-Path -LiteralPath $DesktopPath -PathType Leaf)) { throw "The desktop executable is missing: $DesktopPath" }
    $agentSignature = Get-AuthenticodeSignature -LiteralPath $AgentPath
    $desktopSignature = Get-AuthenticodeSignature -LiteralPath $DesktopPath
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
function Set-JournalDirectoryAcl([string] $ServiceSid) {
    [void][IO.Directory]::CreateDirectory($JournalDirectory)
    $acl = Get-Acl -LiteralPath $JournalDirectory
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($existingRule) }

    $allowedSids = @("S-1-5-18", "S-1-5-32-544", $ServiceSid)
    foreach ($sidText in $allowedSids) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $JournalDirectory -AclObject $acl

    $verified = Get-Acl -LiteralPath $JournalDirectory
    if (-not $verified.AreAccessRulesProtected) { throw "The Agent journal directory is still inheriting permissions." }
    $actualSids = @($verified.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $expectedSids = @($allowedSids | Sort-Object -Unique)
    if (Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids) {
        throw "The Agent journal directory ACL contains an unexpected or missing principal."
    }
    if (@($verified.Access | Where-Object { $_.AccessControlType -ne "Allow" -or $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl }).Count -ne 0) {
        throw "The Agent journal directory ACL contains a non-full-control or deny entry."
    }
}
function Install-AgentService {
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
    Set-JournalDirectoryAcl $sidMatch.Value
    Invoke-Sc @("sdset", $ServiceName, $ServiceDacl)

    $current = Get-ServiceRecord
    if (-not $current -or $current.StartName -notin @("LocalSystem", "NT AUTHORITY\SYSTEM")) {
        throw "The Agent service is not configured to run as LocalSystem."
    }
    if (-not [string]::Equals((Get-RegisteredBinaryPath $current), (Get-NormalizedPath $AgentPath), [StringComparison]::OrdinalIgnoreCase)) {
        throw "The Agent service image path did not match the installed binary."
    }
    Invoke-Sc @("start", $ServiceName)
    Wait-ServiceState "Running"
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
function Prepare-AgentUpgrade {
    $service = Get-ServiceRecord
    if ($service) { Stop-OwnedService }
}

try {
    Assert-Elevated
    $AgentPath = Get-NormalizedPath $AgentPath
    switch ($Mode) {
        "PrepareUpgrade" { Prepare-AgentUpgrade; exit 0 }
        "Install" {
            if ([string]::IsNullOrWhiteSpace($DesktopPath)) { throw "DesktopPath is required for Agent service installation." }
            $DesktopPath = Get-NormalizedPath $DesktopPath
            exit (Install-AgentService)
        }
        "Uninstall" { Remove-AgentService; exit 0 }
    }
} catch {
    Write-Error $_
    exit 1
}
