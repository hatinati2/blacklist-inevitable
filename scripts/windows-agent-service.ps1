[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Stop", "Install", "Remove")]
    [string]$Action,

    [string]$AgentPath,
    [string]$InstallerPath,
    [string]$SignerThumbprintFile
)

$ErrorActionPreference = "Stop"
$ServiceName = "BlacklistInevitableAgent"
$ServiceDisplayName = "blacklist-inevitable Agent"
$ServiceSecurityDescriptor = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"

function Get-AgentService {
    Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Invoke-Sc {
    param([string[]]$ScArguments)

    $scPath = Join-Path $env:WINDIR "System32\sc.exe"
    $output = & $scPath @ScArguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "sc.exe $($ScArguments -join ' ') failed with exit code $exitCode. $($output -join ' ')"
    }
}

function Stop-AgentService {
    $service = Get-AgentService
    if ($null -eq $service) { return }

    try {
        if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(30)
            )
            $service.Refresh()
            if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                throw "The Agent service did not reach the Stopped state."
            }
        }
        # Keep a stopped service from auto-starting against files being replaced.
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
    }
    finally {
        $service.Dispose()
    }
}

function Wait-AgentServiceRemoved {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        $service = Get-AgentService
        if ($null -eq $service) { return }
        $service.Dispose()
        Start-Sleep -Milliseconds 250
    }
    throw "The Agent service is still registered after the delete request."
}

function Remove-AgentService {
    Stop-AgentService
    $service = Get-AgentService
    if ($null -eq $service) { return }
    $service.Dispose()
    Invoke-Sc @("delete", $ServiceName)
    Wait-AgentServiceRemoved
}

function Assert-PinnedAuthenticodePublisher {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedThumbprint
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "A required signed deployment file is missing: $Path"
    }
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode verification failed for $Path (status: $($signature.Status))."
    }
    if ($null -eq $signature.SignerCertificate) {
        throw "The signed deployment file has no signer certificate: $Path"
    }
    $actualThumbprint = ($signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($actualThumbprint -ne $ExpectedThumbprint) {
        throw "The signer of $Path does not match the pinned Agent publisher."
    }
}

function Set-AgentJournalDirectoryAcl {
    $rootDirectory = Join-Path $env:ProgramData "blacklist-inevitable"
    $journalDirectory = Join-Path $rootDirectory "Agent"
    New-Item -ItemType Directory -Path $rootDirectory -Force | Out-Null

    $systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administratorsSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $serviceAccount = [System.Security.Principal.NTAccount]::new("NT SERVICE\$ServiceName")
    $serviceSid = $serviceAccount.Translate([System.Security.Principal.SecurityIdentifier])

    function Set-TrustedDirectoryAcl {
        param([Parameter(Mandatory = $true)][string]$Path)

        $directory = Get-Item -LiteralPath $Path -Force
        if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The Agent state directory must not be a reparse point: $Path"
        }

        $acl = [System.Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner($administratorsSid)
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, $propagation, $allow
        ))
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $administratorsSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, $propagation, $allow
        ))
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $serviceSid,
            [System.Security.AccessControl.FileSystemRights]::Modify,
            $inheritance, $propagation, $allow
        ))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }

    # Secure the parent before creating the child to avoid following a
    # user-planted reparse point beneath ProgramData.
    Set-TrustedDirectoryAcl -Path $rootDirectory
    New-Item -ItemType Directory -Path $journalDirectory -Force | Out-Null
    Set-TrustedDirectoryAcl -Path $journalDirectory
}

function Grant-AgentExecutableReadAccess {
    if ([string]::IsNullOrWhiteSpace($AgentPath)) {
        throw "AgentPath is required before setting service executable permissions."
    }

    $agentFullPath = [System.IO.Path]::GetFullPath($AgentPath)
    $programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
    $resourcesDirectory = Split-Path -Parent $agentFullPath
    $applicationDirectory = Split-Path -Parent $resourcesDirectory
    $serviceAccount = [System.Security.Principal.NTAccount]::new("NT SERVICE\$ServiceName")
    $serviceSid = $serviceAccount.Translate([System.Security.Principal.SecurityIdentifier])
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $propagation = [System.Security.AccessControl.PropagationFlags]::None

    $programFilesAcl = Get-Acl -LiteralPath $programFilesRoot
    $programFilesAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $serviceSid,
        $rights,
        [System.Security.AccessControl.InheritanceFlags]::None,
        $propagation,
        $allow
    ))
    Set-Acl -LiteralPath $programFilesRoot -AclObject $programFilesAcl

    foreach ($directoryPath in @($applicationDirectory, $resourcesDirectory)) {
        $directory = Get-Item -LiteralPath $directoryPath -Force
        if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The Agent executable directory must not be a reparse point: $directoryPath"
        }
        $acl = Get-Acl -LiteralPath $directoryPath
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $serviceSid,
            $rights,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            $propagation,
            $allow
        ))
        Set-Acl -LiteralPath $directoryPath -AclObject $acl
    }

    $agentFile = Get-Item -LiteralPath $agentFullPath -Force
    if (($agentFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The Agent executable must not be a reparse point: $agentFullPath"
    }
    $fileAcl = Get-Acl -LiteralPath $agentFullPath
    $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $serviceSid,
        $rights,
        [System.Security.AccessControl.InheritanceFlags]::None,
        $propagation,
        $allow
    ))
    Set-Acl -LiteralPath $agentFullPath -AclObject $fileAcl
}

function Install-AgentService {
    if ([string]::IsNullOrWhiteSpace($AgentPath) -or
        [string]::IsNullOrWhiteSpace($InstallerPath) -or
        [string]::IsNullOrWhiteSpace($SignerThumbprintFile)) {
        throw "Install requires AgentPath, InstallerPath, and SignerThumbprintFile."
    }

    Stop-AgentService
    if (-not (Test-Path -LiteralPath $SignerThumbprintFile -PathType Leaf)) {
        Write-Warning "The LocalSystem Agent was not installed because the publisher pin is missing."
        return 10
    }

    $expectedThumbprint = (Get-Content -LiteralPath $SignerThumbprintFile -Raw -Encoding ascii).Trim()
    $expectedThumbprint = ($expectedThumbprint -replace '\s', '').ToUpperInvariant()
    if ($expectedThumbprint -notmatch '^[A-F0-9]{40}$') {
        Write-Warning "The LocalSystem Agent was not installed or started because this build has no configured publisher thumbprint."
        return 10
    }

    $agentFullPath = [System.IO.Path]::GetFullPath($AgentPath)
    $programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
    if (-not $agentFullPath.StartsWith($programFilesRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The privileged Agent executable must reside below Program Files."
    }

    Assert-PinnedAuthenticodePublisher -Path $agentFullPath -ExpectedThumbprint $expectedThumbprint
    Assert-PinnedAuthenticodePublisher -Path $InstallerPath -ExpectedThumbprint $expectedThumbprint

    try {
        Remove-AgentService
        $binaryPathArgument = 'binPath= "' + $agentFullPath + '"'
        Invoke-Sc @(
            "create",
            $ServiceName,
            $binaryPathArgument,
            "start= demand",
            "obj= LocalSystem",
            ("DisplayName= `"$ServiceDisplayName`"")
        )
        Invoke-Sc @("sidtype", $ServiceName, "restricted")
        Invoke-Sc @(
            "failure",
            $ServiceName,
            "reset= 86400",
            "actions= restart/5000/restart/30000/restart/60000"
        )
        Invoke-Sc @("failureflag", $ServiceName, "1")
        Invoke-Sc @("sdset", $ServiceName, $ServiceSecurityDescriptor)

        Set-AgentJournalDirectoryAcl
        Grant-AgentExecutableReadAccess
        Invoke-Sc @("config", $ServiceName, "start= auto")
        Start-Service -Name $ServiceName -ErrorAction Stop

        $service = Get-AgentService
        if ($null -eq $service) {
            throw "The Agent service disappeared after registration."
        }
        try {
            $service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(30)
            )
            $service.Refresh()
            if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                throw "The Agent service did not reach the Running state."
            }
        }
        finally {
            $service.Dispose()
        }

        Write-Output "The signed LocalSystem Agent service was installed and started."
        return 0
    }
    catch {
        try {
            Remove-AgentService
        }
        catch {
            Write-Warning "Agent service rollback could not fully remove the service: $_"
        }
        throw
    }
}

try {
    switch ($Action) {
        "Stop" {
            Stop-AgentService
            exit 0
        }
        "Remove" {
            Remove-AgentService
            Write-Output "The Agent service was removed; its recovery journal was preserved."
            exit 0
        }
        "Install" {
            $result = Install-AgentService
            exit $result
        }
    }
}
catch {
    Write-Error $_
    exit 1
}
