$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repoRoot "src-tauri/Cargo.toml"
$tempBase = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { $env:TEMP } else { $env:RUNNER_TEMP }
if ([string]::IsNullOrWhiteSpace($tempBase)) {
    throw "A writable temporary directory could not be resolved."
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this acceptance script from an elevated PowerShell session so it can create a temporary standard user."
}
$root = Join-Path $tempBase ("preflight-acl-" + [Guid]::NewGuid().ToString("N"))
$runDir = Join-Path $root "run"
$config = Join-Path $runDir "config.json"
$userName = "aclprobe" + [Guid]::NewGuid().ToString("N").Substring(0, 10)
$passwordText = [Guid]::NewGuid().ToString("N") + "aA1!"
$securePassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
$createdUser = $false

try {
    Import-Module Microsoft.PowerShell.LocalAccounts -UseWindowsPowerShell -ErrorAction Stop

    Write-Host "Creating an ACL fixture with the production Rust primitive."
    & cargo run --locked --manifest-path $manifest --target x86_64-pc-windows-msvc --bin preflight-acl-fixture -- $root
    if ($LASTEXITCODE -ne 0) {
        throw "The production ACL fixture binary failed."
    }

    $ownContents = Get-Content -LiteralPath $config -Raw -ErrorAction Stop
    if ($ownContents -ne "ACL-ACCEPTANCE-SENTINEL") {
        throw "The intended application identity could not read the ACL fixture."
    }

    $user = New-LocalUser -Name $userName -Password $securePassword -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
    $createdUser = $true
    Add-LocalGroupMember -SID ([System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-545")) -Member "$env:COMPUTERNAME\$userName"

    $credential = [System.Management.Automation.PSCredential]::new(
        "$env:COMPUTERNAME\$userName",
        $securePassword
    )
    $childScript = @'
$ErrorActionPreference = 'Stop'
$root = '__ROOT__'
$runDir = '__RUNDIR__'
$config = '__CONFIG__'
$checks = @(
    @{ Name = 'list preflight root'; Action = { Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop | Out-Null } },
    @{ Name = 'list per-run directory'; Action = { Get-ChildItem -LiteralPath $runDir -Force -ErrorAction Stop | Out-Null } },
    @{ Name = 'read credential-bearing config'; Action = { Get-Content -LiteralPath $config -Raw -ErrorAction Stop | Out-Null } }
)
foreach ($check in $checks) {
    try {
        & ($check.Action)
        [Console]::Error.WriteLine("Unexpectedly succeeded: $($check.Name)")
        exit 41
    } catch {
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.HResult -eq -2147024891) {
            Write-Output "Denied as expected: $($check.Name)"
        } else {
            [Console]::Error.WriteLine("Unexpected error while checking $($check.Name): $($_.Exception.GetType().FullName) / $($_.Exception.Message)")
            exit 42
        }
    }
}
exit 0
'@
    $childScript = $childScript.Replace("__ROOT__", $root.Replace("'", "''"))
    $childScript = $childScript.Replace("__RUNDIR__", $runDir.Replace("'", "''"))
    $childScript = $childScript.Replace("__CONFIG__", $config.Replace("'", "''"))
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $pwsh = (Get-Process -Id $PID).Path
    $process = Start-Process -FilePath $pwsh -Credential $credential -ArgumentList @(
        "-NoProfile", "-NonInteractive", "-EncodedCommand", $encoded
    ) -PassThru -Wait -WindowStyle Hidden

    if ($process.ExitCode -ne 0) {
        throw "The second standard-user ACL denial check failed with exit code $($process.ExitCode)."
    }

    Write-Host "PASS: the current user can read the fixture; a second local standard user cannot list/read it."
}
finally {
    if ($createdUser) {
        Remove-LocalUser -Name $userName -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
