$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repoRoot "src-tauri/Cargo.toml"
$sharedParent = $env:ProgramData
if ([string]::IsNullOrWhiteSpace($sharedParent) -or -not (Test-Path -LiteralPath $sharedParent -PathType Container)) {
    throw "The shared ProgramData parent directory could not be resolved."
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this acceptance script from an elevated PowerShell session so it can create a temporary standard user."
}
$root = Join-Path $sharedParent ("blacklist-inevitable-preflight-acl-" + [Guid]::NewGuid().ToString("N"))
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
    # Resolve the built-in Users SID in this PowerShell process and pass only
    # its localized group name across the WinPS compatibility boundary.
    $usersGroupAccount = ([System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-545")).Translate(
        [System.Security.Principal.NTAccount]
    ).Value
    $usersGroupName = $usersGroupAccount.Split('\')[-1]
    Add-LocalGroupMember -Group $usersGroupName -Member "$env:COMPUTERNAME\$userName"

    # Use a native token impersonation probe instead of starting a second process.
    # This avoids interactive process-launch restrictions on hosted Windows runners
    # while making every filesystem access execute under the second standard-user token.
    $nativeProbe = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class PreflightAclImpersonationProbe {
    private const int Logon32LogonInteractive = 2;
    private const int Logon32ProviderDefault = 0;
    private const int OpenExisting = 3;
    private const uint FileListDirectory = 0x00000001;
    private const uint GenericRead = 0x80000000;
    private const uint ShareAll = 0x00000007;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileAttributeNormal = 0x00000080;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr security, int creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static int OpenError(string path, bool directory) {
        uint access = directory ? FileListDirectory : GenericRead;
        uint flags = directory ? FileFlagBackupSemantics : FileAttributeNormal;
        IntPtr handle = CreateFile(path, access, ShareAll, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (handle == new IntPtr(-1)) return Marshal.GetLastWin32Error();
        CloseHandle(handle);
        return 0;
    }

    public static int[] Check(string user, string domain, string password, string parent, string root, string runDir, string config) {
        IntPtr token;
        if (!LogonUser(user, domain, password, Logon32LogonInteractive, Logon32ProviderDefault, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed for the temporary standard user.");
        try {
            if (!ImpersonateLoggedOnUser(token))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ImpersonateLoggedOnUser failed.");
            try {
                return new int[] { OpenError(parent, true), OpenError(root, true), OpenError(runDir, true), OpenError(config, false) };
            } finally {
                if (!RevertToSelf()) throw new Win32Exception(Marshal.GetLastWin32Error(), "RevertToSelf failed.");
            }
        } finally {
            CloseHandle(token);
        }
    }
}
'@
    Add-Type -TypeDefinition $nativeProbe -ErrorAction Stop
    $errors = [PreflightAclImpersonationProbe]::Check(
        $userName, $env:COMPUTERNAME, $passwordText, $sharedParent, $root, $runDir, $config
    )
    if ($errors[0] -ne 0) {
        throw "Positive control failed: the standard user could not list the shared parent (Win32 error $($errors[0]))."
    }
    $labels = @("preflight root", "per-run directory", "credential-bearing config")
    for ($index = 1; $index -lt $errors.Length; $index++) {
        if ($errors[$index] -ne 5) {
            throw "Expected access denied for $($labels[$index - 1]); native CreateFile returned Win32 error $($errors[$index])."
        }
        Write-Host "Denied as expected: $($labels[$index - 1])"
    }
    Write-Host "PASS: the current user can read the fixture; a second local standard-user token cannot list/read it."

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
