[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Snapshot", "Compare")]
    [string]$Mode,

    [string]$BaselinePath,

    [string]$CurrentSnapshotPath,

    [string]$OutputPath,

    [switch]$RequireTunAdapter,

    [string]$TunInterfaceNamePattern = "tun|wintun|sing.?box|blacklist-inevitable"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-ReadOnlyCapture {
    param(
        [Parameter(Mandatory = $true)][string]$CommandName,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    if ($null -eq (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            available = $false
            succeeded = $false
            data = @()
            error = "Command is not available on this Windows installation."
        }
    }

    try {
        $items = @(& $Action)
        return [pscustomobject]@{
            available = $true
            succeeded = $true
            data = $items
            error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            available = $true
            succeeded = $false
            data = @()
            error = $_.Exception.Message
        }
    }
}

function Invoke-NetshReadOnly {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $netshPath = Join-Path $env:SystemRoot "System32\netsh.exe"
    if (-not (Test-Path -LiteralPath $netshPath -PathType Leaf)) {
        return [pscustomobject]@{
            available = $false
            succeeded = $false
            exitCode = $null
            output = @()
            error = "netsh.exe was not found."
        }
    }

    try {
        # The returned dump is evidence only. This script never executes its lines.
        $lines = @(& $netshPath @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
        return [pscustomobject]@{
            available = $true
            succeeded = ($code -eq 0)
            exitCode = $code
            output = $lines
            error = if ($code -eq 0) { $null } else { "netsh exited with code $code." }
        }
    }
    catch {
        return [pscustomobject]@{
            available = $true
            succeeded = $false
            exitCode = $null
            output = @()
            error = $_.Exception.Message
        }
    }
}

function Convert-PropertyValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [ValueType]) {
        return $Value
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @()
        foreach ($item in $Value) {
            if ($null -eq $item) {
                $items += $null
            }
            elseif ($item -is [string] -or $item -is [bool] -or $item -is [ValueType]) {
                $items += $item
            }
            else {
                $items += [string]$item
            }
        }
        return ,$items
    }

    return [string]$Value
}

function Convert-DnsAddressFamily {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return "Unknown"
    }

    # Get-DnsClientServerAddress exposes MSFT_DNSClientServerAddress.AddressFamily
    # as the native Winsock numeric family: AF_INET=2 and AF_INET6=23.
    # PowerShell's table formatting renders these as IPv4/IPv6, but casting the
    # raw CIM property to string preserves the numeric values.
    $familyText = ([string]$Value).Trim()
    switch -Exact ($familyText) {
        "2" { return "IPv4" }
        "23" { return "IPv6" }
        "IPv4" { return "IPv4" }
        "IPv6" { return "IPv6" }
        "InterNetwork" { return "IPv4" }
        "InterNetworkV6" { return "IPv6" }
        default { return "Unknown:$familyText" }
    }
}

function Get-SelectedProperties {
    param(
        [Parameter(Mandatory = $true)][object]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$PropertyNames
    )

    $values = [ordered]@{}
    $available = @()

    foreach ($name in $PropertyNames) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -ne $property) {
            $available += $name
            $values[$name] = Convert-PropertyValue -Value $property.Value
        }
    }

    return [pscustomobject]@{
        values = [pscustomobject]$values
        availableProperties = @($available)
    }
}


function Convert-RegistryValueForEvidence {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) {
        return [Convert]::ToBase64String($Value)
    }
    if ($Value -is [string[]]) {
        return ,@($Value)
    }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [ValueType]) {
        return $Value
    }
    return [string]$Value
}

function Get-InterfaceRegistryDohEvidence {
    param([AllowNull()][string]$InterfaceGuid)

    if ([string]::IsNullOrWhiteSpace($InterfaceGuid)) {
        return [pscustomobject]@{
            state = "unknown"
            error = "InterfaceGuid is unavailable; the per-interface registry path cannot be derived."
            families = @()
        }
    }

    $parsedGuid = [guid]::Empty
    if (-not [guid]::TryParse($InterfaceGuid, [ref]$parsedGuid)) {
        return [pscustomobject]@{
            state = "unknown"
            error = "InterfaceGuid is malformed; the per-interface registry path cannot be derived."
            families = @()
        }
    }

    $interfaceKey = $null
    $baseKey = $null
    try {
        $guidKey = "{" + $parsedGuid.ToString() + "}"
        $registryPath = "SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guidKey\DohInterfaceSettings"
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Default
        )
        $interfaceKey = $baseKey.OpenSubKey($registryPath, $false)

        if ($null -eq $interfaceKey) {
            return [pscustomobject]@{
                state = "absent"
                error = $null
                families = @(
                    [pscustomobject]@{ family = "IPv4"; branch = "Doh"; state = "absent"; servers = @() },
                    [pscustomobject]@{ family = "IPv6"; branch = "Doh6"; state = "absent"; servers = @() }
                )
            }
        }

        $families = @()
        foreach ($family in @(
            [pscustomobject]@{ name = "IPv4"; branch = "Doh" },
            [pscustomobject]@{ name = "IPv6"; branch = "Doh6" }
        )) {
            $familyKey = $null
            try {
                $familyKey = $interfaceKey.OpenSubKey($family.branch, $false)
                if ($null -eq $familyKey) {
                    $families += [pscustomobject]@{
                        family = $family.name
                        branch = $family.branch
                        state = "absent"
                        servers = @()
                    }
                    continue
                }

                $servers = @()
                foreach ($serverAddress in @($familyKey.GetSubKeyNames() | Sort-Object)) {
                    $serverKey = $null
                    try {
                        $serverKey = $familyKey.OpenSubKey($serverAddress, $false)
                        if ($null -eq $serverKey) {
                            throw "The DoH registry subkey disappeared during observation."
                        }

                        $values = @()
                        foreach ($valueName in @($serverKey.GetValueNames() | Sort-Object)) {
                            $rawValue = $serverKey.GetValue(
                                $valueName,
                                $null,
                                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                            )
                            $valueKind = $serverKey.GetValueKind($valueName)
                            $values += [pscustomobject]@{
                                name = $valueName
                                kind = [string]$valueKind
                                value = Convert-RegistryValueForEvidence -Value $rawValue
                            }
                        }

                        $servers += [pscustomobject]@{
                            serverAddress = $serverAddress
                            values = @($values)
                        }
                    }
                    finally {
                        if ($null -ne $serverKey) { $serverKey.Dispose() }
                    }
                }

                $families += [pscustomobject]@{
                    family = $family.name
                    branch = $family.branch
                    state = "present"
                    servers = @($servers)
                }
            }
            finally {
                if ($null -ne $familyKey) { $familyKey.Dispose() }
            }
        }

        $anyPresent = @($families | Where-Object { $_.state -eq "present" }).Count -gt 0
        $overallState = "absent"
        if ($anyPresent) { $overallState = "present" }
        return [pscustomobject]@{
            state = $overallState
            error = $null
            families = @($families)
        }
    }
    catch {
        return [pscustomobject]@{
            state = "error"
            error = $_.Exception.Message
            families = @()
        }
    }
    finally {
        if ($null -ne $interfaceKey) { $interfaceKey.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
}

function Get-DnsObservation {
    $osCapture = Invoke-ReadOnlyCapture -CommandName "Get-CimInstance" -Action {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    $adapterCapture = Invoke-ReadOnlyCapture -CommandName "Get-NetAdapter" -Action {
        Get-NetAdapter -IncludeHidden -ErrorAction Stop
    }
    $serverCapture = Invoke-ReadOnlyCapture -CommandName "Get-DnsClientServerAddress" -Action {
        Get-DnsClientServerAddress -ErrorAction Stop
    }
    $clientCapture = Invoke-ReadOnlyCapture -CommandName "Get-DnsClient" -Action {
        Get-DnsClient -ErrorAction Stop
    }
    $globalCapture = Invoke-ReadOnlyCapture -CommandName "Get-DnsClientGlobalSetting" -Action {
        Get-DnsClientGlobalSetting -ErrorAction Stop
    }
    $dohCapture = Invoke-ReadOnlyCapture -CommandName "Get-DnsClientDohServerAddress" -Action {
        Get-DnsClientDohServerAddress -ErrorAction Stop
    }
    $nrptCapture = Invoke-ReadOnlyCapture -CommandName "Get-DnsClientNrptRule" -Action {
        Get-DnsClientNrptRule -ErrorAction Stop
    }

    $netshDump = Invoke-NetshReadOnly -Arguments @("dnsclient", "dump")
    $netshGlobal = Invoke-NetshReadOnly -Arguments @("dnsclient", "show", "global")
    $netshState = Invoke-NetshReadOnly -Arguments @("dnsclient", "show", "state")
    $netshEncryption = Invoke-NetshReadOnly -Arguments @("dnsclient", "show", "encryption")

    $adapters = @()
    if ($adapterCapture.succeeded) {
        foreach ($adapter in $adapterCapture.data) {
            $interfaceIndex = [int]$adapter.ifIndex
            $guid = $null
            if ($null -ne $adapter.InterfaceGuid) {
                $guid = ([string]$adapter.InterfaceGuid).Trim().TrimStart([char]'{').TrimEnd([char]'}').ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($guid)) {
                    $guid = $null
                }
            }

            $serverRecords = @()
            if ($serverCapture.succeeded) {
                $serverRecords = @(
                    $serverCapture.data |
                        Where-Object { [int]$_.InterfaceIndex -eq $interfaceIndex } |
                        Sort-Object -Property AddressFamily |
                        ForEach-Object {
                            [pscustomobject]@{
                                addressFamily = Convert-DnsAddressFamily -Value $_.AddressFamily
                                addressFamilyRaw = [string]$_.AddressFamily
                                serverAddresses = @($_.ServerAddresses | ForEach-Object { [string]$_ })
                            }
                        }
                )
            }

            $clientRecords = @()
            if ($clientCapture.succeeded) {
                $clientRecords = @(
                    $clientCapture.data |
                        Where-Object { [int]$_.InterfaceIndex -eq $interfaceIndex } |
                        ForEach-Object {
                            Get-SelectedProperties -InputObject $_ -PropertyNames @(
                                "ConnectionSpecificSuffix",
                                "ConnectionSpecificSuffixSearchList",
                                "RegisterThisConnectionsAddress",
                                "UseSuffixWhenRegistering",
                                "UseDevolution",
                                "EnableMulticast",
                                "EnableLLMNR",
                                "EnableMDNS"
                            )
                        }
                )
            }

            $hardwareInterface = $null
            $hardwareProperty = $adapter.PSObject.Properties["HardwareInterface"]
            if ($null -ne $hardwareProperty) {
                $hardwareInterface = [bool]$hardwareProperty.Value
            }

            $adapters += [pscustomobject]@{
                interfaceGuid = $guid
                interfaceIndex = $interfaceIndex
                name = [string]$adapter.Name
                interfaceDescription = [string]$adapter.InterfaceDescription
                hardwareInterface = $hardwareInterface
                status = [string]$adapter.Status
                macAddress = [string]$adapter.MacAddress
                dnsServerAddresses = @($serverRecords)
                dnsClientSettings = @($clientRecords)
                # This is a version-sensitive, read-only registry cross-check.
                # It is not an authoritative or supported DNS restore contract.
                registryDohEvidence = Get-InterfaceRegistryDohEvidence -InterfaceGuid $guid
            }
        }
    }

    $registryDohErrors = @($adapters | Where-Object { $_.registryDohEvidence.state -in @("error", "unknown") })
    $globalSettings = @()
    if ($globalCapture.succeeded) {
        $globalSettings = @(
            $globalCapture.data | ForEach-Object {
                Get-SelectedProperties -InputObject $_ -PropertyNames @(
                    "UseSuffixSearchList",
                    "SuffixSearchList",
                    "UseDevolution",
                    "DevolutionLevel"
                )
            }
        )
    }

    $dohServers = @()
    if ($dohCapture.succeeded) {
        $dohServers = @(
            $dohCapture.data |
                Sort-Object -Property ServerAddress |
                ForEach-Object {
                    Get-SelectedProperties -InputObject $_ -PropertyNames @(
                        "ServerAddress",
                        "DohTemplate",
                        "AutoUpgrade",
                        "AllowFallbackToUdp"
                    )
                }
        )
    }

    $nrptRules = @()
    if ($nrptCapture.succeeded) {
        $nrptRules = @(
            $nrptCapture.data |
                Sort-Object -Property Namespace |
                ForEach-Object {
                    Get-SelectedProperties -InputObject $_ -PropertyNames @(
                        "Namespace",
                        "NameServers",
                        "DnsSecValidationRequired",
                        "DnsSecIPsecCARestriction",
                        "DirectAccess",
                        "DisplayName",
                        "Comment"
                    )
                }
        )
    }

    $os = $null
    if ($osCapture.succeeded -and $osCapture.data.Count -gt 0) {
        $os = Get-SelectedProperties -InputObject $osCapture.data[0] -PropertyNames @(
            "Caption", "Version", "BuildNumber", "OSArchitecture"
        )
    }

    return [pscustomobject]@{
        schemaVersion = 2
        capturedAtUtc = [DateTime]::UtcNow.ToString("o")
        os = $os
        collection = [pscustomobject]@{
            getCimInstance = [pscustomobject]@{ available = $osCapture.available; succeeded = $osCapture.succeeded; error = $osCapture.error }
            getNetAdapter = [pscustomobject]@{ available = $adapterCapture.available; succeeded = $adapterCapture.succeeded; error = $adapterCapture.error }
            getDnsClientServerAddress = [pscustomobject]@{ available = $serverCapture.available; succeeded = $serverCapture.succeeded; error = $serverCapture.error }
            getDnsClient = [pscustomobject]@{ available = $clientCapture.available; succeeded = $clientCapture.succeeded; error = $clientCapture.error }
            getDnsClientGlobalSetting = [pscustomobject]@{ available = $globalCapture.available; succeeded = $globalCapture.succeeded; error = $globalCapture.error }
            getDnsClientDohServerAddress = [pscustomobject]@{ available = $dohCapture.available; succeeded = $dohCapture.succeeded; error = $dohCapture.error }
            getDnsClientNrptRule = [pscustomobject]@{ available = $nrptCapture.available; succeeded = $nrptCapture.succeeded; error = $nrptCapture.error }
            registryDoh = [pscustomobject]@{
                available = $adapterCapture.succeeded
                succeeded = ($adapterCapture.succeeded -and $registryDohErrors.Count -eq 0)
                error = if ($registryDohErrors.Count -gt 0) { "One or more adapters returned incomplete or inaccessible per-interface DoH registry evidence." } else { $null }
            }
            netshDnsClientDump = [pscustomobject]@{ available = $netshDump.available; succeeded = $netshDump.succeeded; exitCode = $netshDump.exitCode; error = $netshDump.error }
            netshDnsClientShowGlobal = [pscustomobject]@{ available = $netshGlobal.available; succeeded = $netshGlobal.succeeded; exitCode = $netshGlobal.exitCode; error = $netshGlobal.error }
            netshDnsClientShowState = [pscustomobject]@{ available = $netshState.available; succeeded = $netshState.succeeded; exitCode = $netshState.exitCode; error = $netshState.error }
            netshDnsClientShowEncryption = [pscustomobject]@{ available = $netshEncryption.available; succeeded = $netshEncryption.succeeded; exitCode = $netshEncryption.exitCode; error = $netshEncryption.error }
        }
        adapters = @($adapters)
        globalSettings = @($globalSettings)
        dohServerInventory = @($dohServers)
        nrptRules = @($nrptRules)
        evidence = [pscustomobject]@{
            # This is captured as text for review only and is never replayed.
            netshDnsClientDump = @($netshDump.output)
            netshDnsClientShowGlobal = @($netshGlobal.output)
            netshDnsClientShowState = @($netshState.output)
            netshDnsClientShowEncryption = @($netshEncryption.output)
        }
        limitations = @(
            "Get-DnsClientDohServerAddress is a system known-server inventory, not the adapter/profile DoH property arrays in DNS_INTERFACE_SETTINGS3.",
            "Get-DnsClientServerAddress reports configured address lists, not a complete adapter/profile recovery snapshot.",
            "The DHCP-versus-static DNS source mode is retained in raw netsh output for manual review and is not automatically compared by this probe.",
            "Per-interface registry Doh/Doh6 keys are read-only diagnostic evidence; their presence, absence, and value layout are not treated as a supported complete DoH snapshot or restore contract.",
            "This observation does not prove DNS packet containment or absence of leaks; packet capture and live Windows acceptance are separate gates.",
            "netsh dnsclient dump output is evidence only. It is not executed or accepted as a canonical restorable snapshot by this script."
        )
    }
}

function ConvertTo-ComparableJson {
    param([AllowNull()][object]$Value)
    return ConvertTo-Json -InputObject $Value -Depth 16 -Compress
}

function Write-ObservationFile {
    param([Parameter(Mandatory = $true)][object]$Observation)

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $script:OutputPath = Join-Path (Get-Location).Path ("windows-dns-observation-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".json")
    }

    $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $json = ConvertTo-Json -InputObject $Observation -Depth 20
    Set-Content -LiteralPath $fullPath -Value $json -Encoding UTF8
    Write-Host "Observation written to: $fullPath"
}

if ($Mode -eq "Snapshot") {
    $snapshot = Get-DnsObservation
    Write-ObservationFile -Observation $snapshot

    $failed = @(
        $snapshot.collection.PSObject.Properties |
            Where-Object { -not $_.Value.succeeded } |
            Select-Object -ExpandProperty Name
    )
    if ($failed.Count -gt 0) {
        Write-Warning ("Some read-only collectors were unavailable or failed: " + ($failed -join ", "))
    }
    Write-Host "Snapshot captured. This is diagnostic evidence, not an authorization to restore DNS."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($BaselinePath)) {
    throw "-BaselinePath is required when -Mode Compare is selected."
}
if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
    throw "Baseline file does not exist: $BaselinePath"
}

$baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
if ($baseline.schemaVersion -ne 2) {
    throw "Unsupported baseline schema version."
}

if (-not [string]::IsNullOrWhiteSpace($CurrentSnapshotPath)) {
    if (-not (Test-Path -LiteralPath $CurrentSnapshotPath -PathType Leaf)) {
        throw "Current snapshot file does not exist: $CurrentSnapshotPath"
    }
    $current = Get-Content -LiteralPath $CurrentSnapshotPath -Raw | ConvertFrom-Json
    if ($current.schemaVersion -ne 2) {
        throw "Unsupported current snapshot schema version."
    }
}
else {
    $current = Get-DnsObservation
}
$changes = @()
$unknown = @()

$requiredCollectors = @(
    "getNetAdapter",
    "getDnsClientServerAddress",
    "getDnsClient",
    "getDnsClientGlobalSetting",
    "getDnsClientDohServerAddress",
    "getDnsClientNrptRule",
    "registryDoh",
    "netshDnsClientDump"
)

foreach ($collectorName in $requiredCollectors) {
    if (-not $baseline.collection.$collectorName.succeeded) {
        $unknown += "Baseline collector '$collectorName' was not successful."
    }
    if (-not $current.collection.$collectorName.succeeded) {
        $unknown += "Current collector '$collectorName' was not successful."
    }
}

$unclassifiedBaseline = @($baseline.adapters | Where-Object { $null -eq $_.hardwareInterface })
$unclassifiedCurrent = @($current.adapters | Where-Object { $null -eq $_.hardwareInterface })
if ($unclassifiedBaseline.Count -gt 0) {
    $unknown += "One or more baseline adapters could not be classified as physical or virtual."
}
if ($unclassifiedCurrent.Count -gt 0) {
    $unknown += "One or more current adapters could not be classified as physical or virtual."
}

$baselinePhysical = @($baseline.adapters | Where-Object { $_.hardwareInterface -eq $true })
$currentPhysical = @($current.adapters | Where-Object { $_.hardwareInterface -eq $true })

if ($baselinePhysical.Count -eq 0) {
    $unknown += "No physical adapters were identified in the baseline."
}
if ($currentPhysical.Count -eq 0) {
    $unknown += "No physical adapters were identified in the current observation."
}

$baselineIds = @($baselinePhysical | ForEach-Object { [string]$_.interfaceGuid } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$currentIds = @($currentPhysical | ForEach-Object { [string]$_.interfaceGuid } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ($baselineIds.Count -ne $baselinePhysical.Count) {
    $unknown += "At least one baseline physical adapter has no stable InterfaceGuid."
}
if ($currentIds.Count -ne $currentPhysical.Count) {
    $unknown += "At least one current physical adapter has no stable InterfaceGuid."
}
if (@($baselineIds | Select-Object -Unique).Count -ne $baselineIds.Count) {
    $unknown += "Baseline physical adapter InterfaceGuid values are not unique."
}
if (@($currentIds | Select-Object -Unique).Count -ne $currentIds.Count) {
    $unknown += "Current physical adapter InterfaceGuid values are not unique."
}

foreach ($id in $baselineIds) {
    $before = @($baselinePhysical | Where-Object { $_.interfaceGuid -eq $id }) | Select-Object -First 1
    $after = @($currentPhysical | Where-Object { $_.interfaceGuid -eq $id }) | Select-Object -First 1
    if ($null -eq $after) {
        $unknown += "Baseline physical adapter $id is absent from the current observation."
        continue
    }
    if (@($before.dnsClientSettings).Count -eq 0 -or @($after.dnsClientSettings).Count -eq 0) {
        $unknown += "Per-interface DNS Client settings were not returned for physical adapter $id."
    }
    foreach ($adapterObservation in @(
        [pscustomobject]@{ label = "baseline"; adapter = $before },
        [pscustomobject]@{ label = "current"; adapter = $after }
    )) {
        $addressRecords = @($adapterObservation.adapter.dnsServerAddresses)
        if ($addressRecords.Count -eq 0) {
            $unknown += "No DNS server address-family records were returned for physical adapter $id in the $($adapterObservation.label) observation."
            continue
        }
        $observedFamilies = @(
            $addressRecords | ForEach-Object {
                $rawFamilyProperty = $_.PSObject.Properties["addressFamilyRaw"]
                $familyValue = if ($null -ne $rawFamilyProperty) { $rawFamilyProperty.Value } else { $_.addressFamily }
                Convert-DnsAddressFamily -Value $familyValue
            }
        )
        $unrecognizedFamilies = @($observedFamilies | Where-Object { $_ -notin @("IPv4", "IPv6") })
        if ($unrecognizedFamilies.Count -gt 0) {
            $unknown += "One or more DNS address-family records are unrecognized for physical adapter $id in the $($adapterObservation.label) observation: $($unrecognizedFamilies -join ', ')."
        }
        foreach ($family in @("IPv4", "IPv6")) {
            if ($observedFamilies -notcontains $family) {
                $unknown += "The $family DNS server address record is missing for physical adapter $id in the $($adapterObservation.label) observation."
            }
        }
    }
    $requiredClientFields = @("ConnectionSpecificSuffix", "ConnectionSpecificSuffixSearchList", "RegisterThisConnectionsAddress", "UseSuffixWhenRegistering")
    foreach ($record in @($before.dnsClientSettings) + @($after.dnsClientSettings)) {
        $missingClientFields = @($requiredClientFields | Where-Object { $record.availableProperties -notcontains $_ })
        if ($missingClientFields.Count -gt 0) {
            $unknown += "Physical adapter $id is missing DNS Client properties: $($missingClientFields -join ", ")."
        }
    }

    if ((ConvertTo-ComparableJson $before.dnsServerAddresses) -ne (ConvertTo-ComparableJson $after.dnsServerAddresses)) {
        $changes += "DNS server address list changed on physical adapter $id."
    }
    if ((ConvertTo-ComparableJson $before.dnsClientSettings) -ne (ConvertTo-ComparableJson $after.dnsClientSettings)) {
        $changes += "Per-interface DNS Client settings changed on physical adapter $id."
    }
    if ($before.registryDohEvidence.state -in @("error", "unknown") -or $after.registryDohEvidence.state -in @("error", "unknown")) {
        $unknown += "Per-interface registry DoH evidence is incomplete for physical adapter $id."
    }
    elseif ((ConvertTo-ComparableJson $before.registryDohEvidence) -ne (ConvertTo-ComparableJson $after.registryDohEvidence)) {
        $changes += "Read-only registry DoH evidence changed on physical adapter $id."
    }
}

foreach ($id in $currentIds) {
    if ($baselineIds -notcontains $id) {
        $unknown += "A new physical adapter $id appeared after the baseline."
    }
}

if (@($baseline.globalSettings).Count -eq 0 -or @($current.globalSettings).Count -eq 0) {
    $unknown += "Global DNS suffix/devolution settings were not returned."
}
else {
    $requiredGlobalFields = @("UseSuffixSearchList", "SuffixSearchList", "UseDevolution", "DevolutionLevel")
    foreach ($record in @($baseline.globalSettings) + @($current.globalSettings)) {
        $missingGlobalFields = @($requiredGlobalFields | Where-Object { $record.availableProperties -notcontains $_ })
        if ($missingGlobalFields.Count -gt 0) {
            $unknown += "Global DNS settings are missing properties: $($missingGlobalFields -join ", ")."
        }
    }
}

foreach ($record in @($baseline.dohServerInventory) + @($current.dohServerInventory)) {
    $requiredDohFields = @("ServerAddress", "DohTemplate", "AutoUpgrade", "AllowFallbackToUdp")
    $missingDohFields = @($requiredDohFields | Where-Object { $record.availableProperties -notcontains $_ })
    if ($missingDohFields.Count -gt 0) {
        $unknown += "A DoH inventory record is missing properties: $($missingDohFields -join ", ")."
    }
}

foreach ($record in @($baseline.nrptRules) + @($current.nrptRules)) {
    $requiredNrptFields = @("Namespace", "NameServers")
    $missingNrptFields = @($requiredNrptFields | Where-Object { $record.availableProperties -notcontains $_ })
    if ($missingNrptFields.Count -gt 0) {
        $unknown += "An NRPT rule is missing properties: $($missingNrptFields -join ", ")."
    }
}

if ($null -eq $baseline.os -or $null -eq $current.os) {
    $unknown += "Windows version/build information was not available in both observations."
}
elseif ((ConvertTo-ComparableJson $baseline.os.values) -ne (ConvertTo-ComparableJson $current.os.values)) {
    $unknown += "Windows version/build information changed between baseline and current observations."
}

foreach ($propertyName in @("globalSettings", "dohServerInventory", "nrptRules")) {
    if ((ConvertTo-ComparableJson $baseline.$propertyName) -ne (ConvertTo-ComparableJson $current.$propertyName)) {
        $changes += "Global DNS evidence '$propertyName' changed."
    }
}

$baselineAdapterIds = @($baseline.adapters | ForEach-Object { [string]$_.interfaceGuid })
$newVirtualAdapters = @(
    $current.adapters |
        Where-Object {
            $_.hardwareInterface -eq $false -and
            -not [string]::IsNullOrWhiteSpace([string]$_.interfaceGuid) -and
            $baselineAdapterIds -notcontains [string]$_.interfaceGuid
        } |
        ForEach-Object {
            [pscustomobject]@{
                interfaceGuid = $_.interfaceGuid
                interfaceIndex = $_.interfaceIndex
                name = $_.name
                interfaceDescription = $_.interfaceDescription
                dnsServerAddresses = $_.dnsServerAddresses
            }
        }
)

$tunMatches = @(
    $current.adapters |
        Where-Object {
            $_.hardwareInterface -eq $false -and
            (("{0} {1}" -f $_.name, $_.interfaceDescription) -match $TunInterfaceNamePattern)
        }
)

if ($RequireTunAdapter -and $tunMatches.Count -eq 0) {
    $unknown += "No virtual adapter matched TunInterfaceNamePattern '$TunInterfaceNamePattern'."
}

$status = "PASS"
if ($changes.Count -gt 0) {
    $status = "FAIL"
}
elseif ($unknown.Count -gt 0) {
    $status = "UNKNOWN"
}

$result = [pscustomobject]@{
    schemaVersion = 1
    comparedAtUtc = [DateTime]::UtcNow.ToString("o")
    status = $status
    meaning = "PASS means only that the observed physical-adapter DNS server lists, selected DNS Client fields, selected read-only registry DoH evidence, and selected global DNS evidence were unchanged. DHCP/static source mode is not automatically compared. Registry DoH data is diagnostic only. This is not proof of DNS leak freedom or a complete restorable DNS snapshot."
    baselinePath = [System.IO.Path]::GetFullPath($BaselinePath)
    currentSnapshotPath = if ([string]::IsNullOrWhiteSpace($CurrentSnapshotPath)) { $null } else { [System.IO.Path]::GetFullPath($CurrentSnapshotPath) }
    changes = @($changes)
    unknown = @($unknown)
    newVirtualAdapters = @($newVirtualAdapters)
    tunAdapterMatches = @(
        $tunMatches | ForEach-Object {
            [pscustomobject]@{
                interfaceGuid = $_.interfaceGuid
                interfaceIndex = $_.interfaceIndex
                name = $_.name
                interfaceDescription = $_.interfaceDescription
                dnsServerAddresses = $_.dnsServerAddresses
            }
        }
    )
    currentObservation = $current
}

Write-ObservationFile -Observation $result
Write-Host "Physical DNS comparison status: $status"
foreach ($change in $changes) { Write-Host "CHANGE: $change" }
foreach ($item in $unknown) { Write-Warning $item }

if ($status -eq "FAIL") { exit 1 }
if ($status -eq "UNKNOWN") { exit 2 }
exit 0
