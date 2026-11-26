[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$source = 'Get-DnsClientDohServerAddress'
$requiredProperties = @('ServerAddress', 'DohTemplate', 'AutoUpgrade', 'AllowFallbackToUdp')
$maxRows = 64

function Write-Result {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result,
        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    $json = ConvertTo-Json -InputObject $Result -Depth 12 -Compress
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $parent = Split-Path -Parent $OutputPath
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
    }
    Write-Output $json
    exit $ExitCode
}

try {
    # Record only OS build metadata needed to identify a client test machine.
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $os) {
        throw 'Win32_OperatingSystem returned no local operating-system record.'
    }

    $build = 0
    if (-not [int]::TryParse([string]$os.BuildNumber, [ref]$build)) {
        throw 'Windows returned an invalid operating-system build number.'
    }

    $isClient = [int]$os.ProductType -eq 1
    $platform = if (-not $isClient) {
        'WindowsServer'
    } elseif ($build -ge 22000) {
        'Windows11'
    } elseif ($build -ge 19041) {
        'Windows10'
    } else {
        'UnsupportedWindowsClientBuild'
    }

    $module = Get-Module -ListAvailable -Name DnsClient |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1

    $metadata = [ordered]@{
        os_caption = [string]$os.Caption
        os_version = [string]$os.Version
        os_build = $build
        os_product_type = [int]$os.ProductType
        platform = $platform
        powershell_version = [string]$PSVersionTable.PSVersion
        dnsclient_module_version = if ($null -ne $module) { [string]$module.Version } else { $null }
        source = $source
    }

    if ($platform -eq 'WindowsServer' -or $platform -eq 'UnsupportedWindowsClientBuild') {
        Write-Result -Result ([ordered]@{
            status = 'UnsupportedPlatform'
            metadata = $metadata
            rows = @()
            message = 'Run this acceptance probe on a supported Windows 10 or Windows 11 client machine.'
        }) -ExitCode 3
    }

    $cmdlet = Get-Command -Name $source -CommandType Cmdlet -ErrorAction SilentlyContinue
    if ($null -eq $cmdlet) {
        Write-Result -Result ([ordered]@{
            status = 'CapabilityUnavailable'
            metadata = $metadata
            rows = @()
            message = 'The local Windows image does not expose Get-DnsClientDohServerAddress. This is Unknown, not an empty DoH inventory.'
        }) -ExitCode 3
    }

    # This is the only DNS-specific command invoked by the script. It is a
    # read-only Get cmdlet; no Add/Set/Remove cmdlets or registry writes occur.
    $items = @(Get-DnsClientDohServerAddress -ErrorAction Stop | Select-Object -First ($maxRows + 1))
    if ($items.Count -gt $maxRows) {
        Write-Result -Result ([ordered]@{
            status = 'InventoryTooLarge'
            metadata = $metadata
            row_count_observed = $items.Count
            rows = @()
            message = 'The returned DoH inventory exceeds the 64-row acceptance bound.'
        }) -ExitCode 2
    }

    if ($items.Count -eq 0) {
        Write-Result -Result ([ordered]@{
            status = 'SuccessfulEmptyInventorySchemaUnobserved'
            metadata = $metadata
            row_count = 0
            property_schema = $null
            rows = @()
            message = 'The Get query succeeded but returned no rows; property names/types cannot be verified on this machine.'
        }) -ExitCode 0
    }

    $observedSchema = $null
    $seenAddresses = @{}
    $rows = @()

    foreach ($item in $items) {
        $cimProperties = @($item.CimInstanceProperties)
        if ($cimProperties.Count -eq 0) {
            throw 'A returned item is not exposing CIM instance properties.'
        }

        $names = @($cimProperties | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
        $types = [ordered]@{}
        $values = [ordered]@{}

        foreach ($name in $requiredProperties) {
            $matches = @($cimProperties | Where-Object { $_.Name -ceq $name })
            if ($matches.Count -ne 1) {
                throw "A DoH row must expose exactly one '$name' CIM property."
            }
            $property = $matches[0]
            $types[$name] = [string]$property.CimType
            $values[$name] = $property.Value
        }

        if ($null -eq $observedSchema) {
            $observedSchema = [ordered]@{
                property_names = $names
                required_property_types = $types
            }
        } else {
            if (($observedSchema.property_names -join '|') -ne ($names -join '|')) {
                throw 'DoH rows returned inconsistent CIM property names.'
            }
            foreach ($name in $requiredProperties) {
                if ($observedSchema.required_property_types[$name] -ne $types[$name]) {
                    throw "DoH rows returned inconsistent CIM type metadata for '$name'."
                }
            }
        }

        $expectedTypes = @{
            ServerAddress = 'String'
            DohTemplate = 'String'
            AutoUpgrade = 'Boolean'
            AllowFallbackToUdp = 'Boolean'
        }
        foreach ($name in $requiredProperties) {
            if ($types[$name] -ne $expectedTypes[$name]) {
                throw "The '$name' CIM type was '$($types[$name])', expected '$($expectedTypes[$name])'."
            }
            if ($null -eq $values[$name]) {
                throw "The required DoH value '$name' was null."
            }
        }

        $addressText = [string]$values.ServerAddress
        $parsedAddress = $null
        if ([string]::IsNullOrWhiteSpace($addressText) -or
            -not [System.Net.IPAddress]::TryParse($addressText, [ref]$parsedAddress)) {
            throw 'A DoH row returned a malformed ServerAddress.'
        }
        if ($parsedAddress.Equals([System.Net.IPAddress]::Any) -or
            $parsedAddress.Equals([System.Net.IPAddress]::IPv6Any) -or
            $parsedAddress.IsIPv6Multicast -or
            ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
                ([byte[]]$parsedAddress.GetAddressBytes())[0] -ge 224 -and
                ([byte[]]$parsedAddress.GetAddressBytes())[0] -le 239)) {
            throw 'A DoH row returned a non-unicast server address.'
        }
        $addressKey = $parsedAddress.ToString().ToLowerInvariant()
        if ($seenAddresses.ContainsKey($addressKey)) {
            throw 'The DoH inventory contains a duplicate server address.'
        }
        $seenAddresses[$addressKey] = $true

        $template = [string]$values.DohTemplate
        if ([string]::IsNullOrWhiteSpace($template) -or
            $template.Length -gt 2048 -or
            $template.Contains('#') -or
            $template.Contains([char]0) -or
            $template -match '[\x00-\x1F\x7F]') {
            throw 'A DoH URI template is empty, malformed, or oversized.'
        }
        $sanitizedTemplate = $template.Replace('{?dns}', '?dns=').Replace('{dns}', 'dns')
        if ($sanitizedTemplate.Contains('{') -or $sanitizedTemplate.Contains('}')) {
            throw 'A DoH URI template contains an unsupported template expression.'
        }
        $uri = $null
        if (-not [Uri]::TryCreate($sanitizedTemplate, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -ne 'https' -or
            [string]::IsNullOrWhiteSpace($uri.Host) -or
            -not [string]::IsNullOrEmpty($uri.UserInfo) -or
            -not [string]::IsNullOrEmpty($uri.Fragment)) {
            throw 'A DoH URI template must be an absolute HTTPS URI without credentials or fragment.'
        }

        if ($values.AutoUpgrade -isnot [bool] -or $values.AllowFallbackToUdp -isnot [bool]) {
            throw 'DoH boolean properties did not return Boolean values.'
        }

        $rows += [ordered]@{
            server_address = $addressText
            doh_template = $template
            auto_upgrade = [bool]$values.AutoUpgrade
            allow_fallback_to_udp = [bool]$values.AllowFallbackToUdp
            property_types = $types
        }
    }

    Write-Result -Result ([ordered]@{
        status = 'Accepted'
        metadata = $metadata
        row_count = $rows.Count
        property_schema = $observedSchema
        rows = $rows
        message = 'The local, read-only DoH known-server inventory and live CIM property schema passed validation.'
    }) -ExitCode 0
}
catch {
    $detail = [string]$_.Exception.Message
    if ($detail.Length -gt 256) {
        $detail = $detail.Substring(0, 256)
    }
    Write-Result -Result ([ordered]@{
        status = 'ValidationFailed'
        source = $source
        error = $detail
        rows = @()
        message = 'The DoH inventory is incomplete or failed validation. Treat it as Unknown.'
    }) -ExitCode 2
}
