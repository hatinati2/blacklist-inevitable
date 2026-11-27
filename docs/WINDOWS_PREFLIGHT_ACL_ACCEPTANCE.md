# Windows preflight ACL acceptance

This check verifies the actual Windows access-control boundary using the production Rust creation primitive.

## Supported device check

Run on a supported Windows 10 or Windows 11 desktop from an elevated PowerShell session, with the repository checked out and the Rust MSVC toolchain installed:

```powershell
pwsh -NoProfile -File .\scripts\windows-preflight-acl-acceptance.ps1
```

The script:

1. Builds and runs the small `preflight-acl-fixture` binary, which calls the same private-directory and private-file functions used by the app.
2. Confirms the creating identity can read the fixture config.
3. Creates a random temporary local account and explicitly places it in the built-in Users group (not Administrators).
4. Runs a separate PowerShell process under that second identity and expects access denied for listing the preflight root, listing the per-run directory, and reading the config file.
5. Removes the temporary local account and fixture directory in a `finally` block.

The fixture contains only the literal test marker `ACL-ACCEPTANCE-SENTINEL`; it does not use real profile credentials. The account password is generated for the test and is not written to the repository or printed.

## Acceptance record

For each supported OS build tested, record the Windows edition/build, whether the script completed successfully, and its three `Denied as expected` results. A successful hosted Windows CI run is useful regression coverage, but keep this device check as a release acceptance item for Windows 10 and Windows 11 separately.

Do not mark the ACL work fully accepted if the second identity can list or read any fixture object, or if the script fails for a reason other than the expected access-denied result.
