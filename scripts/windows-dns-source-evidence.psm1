Set-StrictMode -Version Latest

function ConvertTo-DnsAddressFamilyLabel {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return "Unknown" }
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

function ConvertFrom-NetshInterfaceDnsDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("IPv4", "IPv6")]
        [string]$AddressFamily,

        [AllowEmptyCollection()]
        [string[]]$Lines = @()
    )

    $records = @()
    $unrecognizedRecords = @()
    $unrecognizedLineCount = 0
    $identityPattern = '^\s*set\s+dnsservers\s+(?:name=)?(?:"(?<quotedName>[^"]*)"|(?<bareName>[^\s]+))(?:\s+source=(?<source>[^\s]+))?'
    $pattern = '^\s*set\s+dnsservers\s+(?:name=)?(?:"(?<quotedName>[^"]*)"|(?<bareName>[^\s]+))\s+source=(?<source>dhcp|static)(?:\s|$)'

    foreach ($line in $Lines) {
        $text = [string]$line
        if ($text -notmatch '(?i)^\s*set\s+dnsservers\b') {
            continue
        }

        $match = [regex]::Match(
            $text,
            $pattern,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        if (-not $match.Success) {
            $identityMatch = [regex]::Match(
                $text,
                $identityPattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
            if (-not $identityMatch.Success) {
                # The malformed set command cannot be attributed to an adapter;
                # fail closed for this family rather than risk a wrong mapping.
                $unrecognizedLineCount++
                continue
            }
            $invalidAlias = if ($identityMatch.Groups["quotedName"].Success) {
                $identityMatch.Groups["quotedName"].Value
            }
            else {
                $identityMatch.Groups["bareName"].Value
            }
            $unrecognizedRecords += [pscustomobject]@{
                interfaceAlias = $invalidAlias
                sourceToken = if ($identityMatch.Groups["source"].Success) { $identityMatch.Groups["source"].Value } else { $null }
            }
            continue
        }

        $interfaceAlias = if ($match.Groups["quotedName"].Success) {
            $match.Groups["quotedName"].Value
        }
        else {
            $match.Groups["bareName"].Value
        }
        $sourceToken = $match.Groups["source"].Value.ToLowerInvariant()

        if ([string]::IsNullOrWhiteSpace($interfaceAlias) -or $sourceToken -notin @("dhcp", "static")) {
            $unrecognizedLineCount++
            continue
        }

        $sourceMode = if ($sourceToken -eq "static") { "Static" } else { "Automatic" }
        $records += [pscustomobject]@{
            addressFamily = $AddressFamily
            interfaceAlias = $interfaceAlias
            sourceToken = $sourceToken
            sourceMode = $sourceMode
        }
    }

    return [pscustomobject]@{
        addressFamily = $AddressFamily
        records = @($records)
        unrecognizedRecords = @($unrecognizedRecords)
        unrecognizedLineCount = $unrecognizedLineCount
    }
}

function Get-NetshInterfaceDnsSourceForAdapter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ParsedEvidence,

        [Parameter(Mandatory = $true)]
        [string]$InterfaceAlias
    )

    if ($ParsedEvidence.unrecognizedLineCount -gt 0) {
        return [pscustomobject]@{
            state = "unknown"
            sourceMode = "Unknown"
            sourceToken = $null
            interfaceAlias = $InterfaceAlias
            reason = "One or more DNS source statements could not be attributed to a specific adapter."
        }
    }

    $invalidMatches = @(
        $ParsedEvidence.unrecognizedRecords |
            Where-Object { [string]$_.interfaceAlias -ieq $InterfaceAlias }
    )
    if ($invalidMatches.Count -gt 0) {
        return [pscustomobject]@{
            state = "unknown"
            sourceMode = "Unknown"
            sourceToken = $null
            interfaceAlias = $InterfaceAlias
            reason = "The source statement for this adapter is malformed or uses an unsupported source token."
        }
    }

    $matches = @(
        $ParsedEvidence.records |
            Where-Object { [string]$_.interfaceAlias -ieq $InterfaceAlias }
    )
    if ($matches.Count -eq 0) {
        return [pscustomobject]@{
            state = "unknown"
            sourceMode = "Unknown"
            sourceToken = $null
            interfaceAlias = $InterfaceAlias
            reason = "No per-family DNS source statement was found for this adapter."
        }
    }
    if ($matches.Count -ne 1) {
        return [pscustomobject]@{
            state = "ambiguous"
            sourceMode = "Unknown"
            sourceToken = $null
            interfaceAlias = $InterfaceAlias
            reason = "Multiple per-family DNS source statements matched this adapter."
        }
    }

    return [pscustomobject]@{
        state = "observed"
        sourceMode = [string]$matches[0].sourceMode
        sourceToken = [string]$matches[0].sourceToken
        interfaceAlias = $InterfaceAlias
        reason = $null
    }
}


function ConvertFrom-NetshIPv6InterfaceDump {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Lines = @()
    )

    $records = @()
    $unrecognizedRecords = @()
    $unrecognizedLineCount = 0
    $identityPattern = '^\s*set\s+interface\s+(?:interface=)?(?:"(?<quotedName>[^"]*)"|(?<bareName>[^\s]+))'
    $settingDefinitions = @(
        [pscustomobject]@{ property = "routerDiscovery"; token = "routerdiscovery"; allowed = @("enabled", "disabled", "dhcp") },
        [pscustomobject]@{ property = "managedAddress"; token = "managedaddress"; allowed = @("enabled", "disabled") },
        [pscustomobject]@{ property = "otherStateful"; token = "otherstateful"; allowed = @("enabled", "disabled") },
        [pscustomobject]@{ property = "raBasedDnsConfig"; token = "rabaseddnsconfig"; allowed = @("enabled", "disabled") },
        [pscustomobject]@{ property = "dhcpStaticIpCoexistence"; token = "dhcpstaticipcoexistence"; allowed = @("enabled", "disabled") }
    )

    foreach ($line in $Lines) {
        $text = [string]$line
        if ($text -notmatch '(?i)^\s*set\s+interface\b') {
            continue
        }

        $identityMatch = [regex]::Match(
            $text,
            $identityPattern,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        if (-not $identityMatch.Success) {
            $unrecognizedLineCount++
            continue
        }

        $interfaceAlias = if ($identityMatch.Groups["quotedName"].Success) {
            $identityMatch.Groups["quotedName"].Value
        }
        else {
            $identityMatch.Groups["bareName"].Value
        }
        if ([string]::IsNullOrWhiteSpace($interfaceAlias)) {
            $unrecognizedLineCount++
            continue
        }

        $values = [ordered]@{}
        $available = @()
        $invalidTokens = @()
        foreach ($definition in $settingDefinitions) {
            $tokenPattern = "(?i)(?:^|\s)$($definition.token)=(?<value>[^\s]+)(?=\s|$)"
            $tokenMatch = [regex]::Match($text, $tokenPattern)
            if (-not $tokenMatch.Success) {
                continue
            }
            $rawValue = $tokenMatch.Groups["value"].Value.ToLowerInvariant()
            if ($rawValue -notin $definition.allowed) {
                $invalidTokens += $definition.token
                continue
            }
            $values[$definition.property] = $rawValue
            $available += $definition.property
        }

        if ($invalidTokens.Count -gt 0) {
            $unrecognizedRecords += [pscustomobject]@{
                interfaceAlias = $interfaceAlias
                invalidTokens = @($invalidTokens)
            }
        }

        $records += [pscustomobject]@{
            interfaceAlias = $interfaceAlias
            settings = [pscustomobject]$values
            availableProperties = @($available)
        }
    }

    return [pscustomobject]@{
        records = @($records)
        unrecognizedRecords = @($unrecognizedRecords)
        unrecognizedLineCount = $unrecognizedLineCount
    }
}

function Get-NetshIPv6InterfaceDnsPolicyForAdapter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ParsedEvidence,

        [Parameter(Mandatory = $true)]
        [string]$InterfaceAlias
    )

    if ($ParsedEvidence.unrecognizedLineCount -gt 0) {
        return [pscustomobject]@{
            state = "unknown"
            interfaceAlias = $InterfaceAlias
            settings = [pscustomobject]@{}
            availableProperties = @()
            reason = "One or more IPv6 interface settings statements could not be attributed to an adapter."
        }
    }

    $invalidMatches = @(
        $ParsedEvidence.unrecognizedRecords |
            Where-Object { [string]$_.interfaceAlias -ieq $InterfaceAlias }
    )
    if ($invalidMatches.Count -gt 0) {
        return [pscustomobject]@{
            state = "unknown"
            interfaceAlias = $InterfaceAlias
            settings = [pscustomobject]@{}
            availableProperties = @()
            reason = "An IPv6 interface policy token is malformed or has an unsupported value."
        }
    }

    $matches = @(
        $ParsedEvidence.records |
            Where-Object { [string]$_.interfaceAlias -ieq $InterfaceAlias }
    )
    if ($matches.Count -eq 0) {
        return [pscustomobject]@{
            state = "unknown"
            interfaceAlias = $InterfaceAlias
            settings = [pscustomobject]@{}
            availableProperties = @()
            reason = "No IPv6 set-interface policy statement was found for this adapter."
        }
    }
    if ($matches.Count -ne 1) {
        return [pscustomobject]@{
            state = "ambiguous"
            interfaceAlias = $InterfaceAlias
            settings = [pscustomobject]@{}
            availableProperties = @()
            reason = "Multiple IPv6 set-interface policy statements matched this adapter."
        }
    }

    $requiredProperties = @("routerDiscovery", "managedAddress", "otherStateful", "raBasedDnsConfig", "dhcpStaticIpCoexistence")
    $missingProperties = @($requiredProperties | Where-Object { $matches[0].availableProperties -notcontains $_ })
    $state = if ($missingProperties.Count -eq 0) { "observed" } else { "unknown" }
    return [pscustomobject]@{
        state = $state
        interfaceAlias = $InterfaceAlias
        settings = $matches[0].settings
        availableProperties = @($matches[0].availableProperties)
        reason = if ($missingProperties.Count -eq 0) { $null } else { "IPv6 interface policy is missing: $($missingProperties -join ', ')." }
    }
}



function ConvertFrom-NetshDnsClientDump {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Lines = @()
    )

    $dnsServerCommands = @()
    $encryptionCommands = @()
    $globalCommands = @()
    $interfaceCommands = @()
    $malformedStatements = @()
    $unsupportedStatements = @()
    $recognizedCommandCount = 0
    $lineNumber = 0

    foreach ($line in $Lines) {
        $lineNumber++
        $text = [string]$line
        $commandMatch = [regex]::Match(
            $text,
            '^\s*(?:(?:netsh)\s+)?(?:dnsclient\s+)?(?<verb>set|add|delete)\s+(?<section>dnsserver|encryption|global|interface)\b(?<arguments>.*)',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        if (-not $commandMatch.Success) {
            $unsupportedMatch = [regex]::Match(
                $text,
                '^\s*(?:(?:netsh)\s+)?(?:dnsclient\s+)?(?<verb>set|add|delete)\s+(?<section>[A-Za-z][A-Za-z0-9]*)\b',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
            if ($unsupportedMatch.Success) {
                $unsupportedStatements += [pscustomobject]@{
                    lineNumber = $lineNumber
                    verb = $unsupportedMatch.Groups["verb"].Value.ToLowerInvariant()
                    section = $unsupportedMatch.Groups["section"].Value.ToLowerInvariant()
                }
            }
            continue
        }

        $verb = $commandMatch.Groups["verb"].Value.ToLowerInvariant()
        $section = $commandMatch.Groups["section"].Value.ToLowerInvariant()
        if ($verb -eq "delete") {
            $unsupportedStatements += [pscustomobject]@{
                lineNumber = $lineNumber
                verb = $verb
                section = $section
            }
            continue
        }

        $arguments = $commandMatch.Groups["arguments"].Value
        $tokenMatches = [regex]::Matches(
            $arguments,
            '(?<key>[A-Za-z][A-Za-z0-9]*)=(?:"(?<quoted>[^"]*)"|(?<bare>[^\s]+))'
        )
        $unparsedText = [regex]::Replace(
            $arguments,
            '(?<key>[A-Za-z][A-Za-z0-9]*)=(?:"[^"]*"|[^\s]+)',
            ''
        ).Trim()
        $tokens = [ordered]@{}
        $duplicateKeys = @()
        foreach ($tokenMatch in $tokenMatches) {
            $key = $tokenMatch.Groups["key"].Value.ToLowerInvariant()
            $value = if ($tokenMatch.Groups["quoted"].Success) {
                $tokenMatch.Groups["quoted"].Value
            }
            else {
                $tokenMatch.Groups["bare"].Value
            }
            if ($tokens.Contains($key)) {
                $duplicateKeys += $key
                continue
            }
            $tokens[$key] = $value
        }

        $reason = $null
        if ($tokenMatches.Count -eq 0) {
            $reason = "No key/value arguments were parsed."
        }
        elseif (-not [string]::IsNullOrWhiteSpace($unparsedText)) {
            $reason = "The command contains unparsed argument text."
        }
        elseif ($duplicateKeys.Count -gt 0) {
            $reason = "The command contains duplicate option keys."
        }

        $allowedKeys = @()
        switch ($section) {
            "dnsserver" {
                if ($verb -eq "set") { $allowedKeys = @("name", "source", "address", "register", "validate") }
                else { $allowedKeys = @("name", "address", "index", "validate") }
            }
            "encryption" {
                $allowedKeys = @("server", "dohtemplate", "dothost", "autoupgrade", "udpfallback")
            }
            "global" {
                $allowedKeys = @("doh", "dot", "ddr")
            }
            "interface" {
                $allowedKeys = @("name", "ddr", "ddrfallback")
            }
        }
        $unknownKeys = @($tokens.Keys | Where-Object { $allowedKeys -notcontains $_ })
        if ($null -eq $reason -and $unknownKeys.Count -gt 0) {
            $reason = "The command contains unsupported option keys."
        }

        $alias = if ($tokens.Contains("name")) { [string]$tokens["name"] } else { $null }
        if ($null -eq $reason) {
            switch ($section) {
                "dnsserver" {
                    if ([string]::IsNullOrWhiteSpace($alias)) {
                        $reason = "The DNS server command is missing its interface name."
                    }
                    elseif ($verb -eq "set") {
                        if (-not $tokens.Contains("source") -or $tokens["source"].ToLowerInvariant() -notin @("dhcp", "static")) {
                            $reason = "The DNS server source is missing or unsupported."
                        }
                        elseif ($tokens.Contains("address") -and $tokens["address"] -ne "none") {
                            $parsedAddress = $null
                            if (-not [System.Net.IPAddress]::TryParse([string]$tokens["address"], [ref]$parsedAddress)) {
                                $reason = "The DNS server address is not a valid IP address."
                            }
                        }
                    }
                    elseif (-not $tokens.Contains("address")) {
                        $reason = "The add-dnsserver command is missing its address."
                    }
                    else {
                        $parsedAddress = $null
                        if (-not [System.Net.IPAddress]::TryParse([string]$tokens["address"], [ref]$parsedAddress)) {
                            $reason = "The added DNS server address is not a valid IP address."
                        }
                        elseif ($tokens.Contains("index")) {
                            $parsedIndex = 0
                            if (-not [int]::TryParse([string]$tokens["index"], [ref]$parsedIndex) -or $parsedIndex -lt 1) {
                                $reason = "The DNS server index is not a positive integer."
                            }
                        }
                    }
                    if ($null -eq $reason -and $tokens.Contains("register") -and $tokens["register"].ToLowerInvariant() -notin @("none", "primary", "both")) {
                        $reason = "The DNS registration option is unsupported."
                    }
                    if ($null -eq $reason -and $tokens.Contains("validate") -and $tokens["validate"].ToLowerInvariant() -notin @("yes", "no")) {
                        $reason = "The DNS validation option is unsupported."
                    }
                    if ($null -eq $reason) {
                        $addressFamily = $null
                        if ($tokens.Contains("address") -and $tokens["address"] -ne "none") {
                            $parsedAddress = [System.Net.IPAddress]::Parse([string]$tokens["address"])
                            $addressFamily = if ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "IPv4" } elseif ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { "IPv6" } else { "Unknown" }
                        }
                        $dnsServerCommands += [pscustomobject]@{
                            lineNumber = $lineNumber
                            verb = $verb
                            interfaceAlias = $alias
                            source = if ($tokens.Contains("source")) { $tokens["source"].ToLowerInvariant() } else { $null }
                            address = if ($tokens.Contains("address")) { $tokens["address"] } else { $null }
                            addressFamily = $addressFamily
                            index = if ($tokens.Contains("index")) { [int]$tokens["index"] } else { $null }
                            register = if ($tokens.Contains("register")) { $tokens["register"].ToLowerInvariant() } else { $null }
                            validate = if ($tokens.Contains("validate")) { $tokens["validate"].ToLowerInvariant() } else { $null }
                        }
                    }
                }
                "encryption" {
                    if (-not $tokens.Contains("server")) {
                        $reason = "The encryption command is missing its server address."
                    }
                    else {
                        $parsedAddress = $null
                        if (-not [System.Net.IPAddress]::TryParse([string]$tokens["server"], [ref]$parsedAddress)) {
                            $reason = "The encryption server is not a valid IP address."
                        }
                        elseif (-not $tokens.Contains("dohtemplate") -or -not $tokens.Contains("dothost")) {
                            $reason = "The encryption command must include both a DoH template and a DoT host."
                        }
                        else {
                            $dotHostValue = [string]$tokens["dothost"]
                            if ($dotHostValue -ne ":") {
                                $dotHostMatch = [regex]::Match($dotHostValue, '^(?<host>[^:\s]+):(?<port>[0-9]{1,5})')
                                $dotPort = 0
                                if (-not $dotHostMatch.Success -or $dotHostMatch.Length -ne $dotHostValue.Length -or
                                    -not [int]::TryParse([string]$dotHostMatch.Groups["port"].Value, [ref]$dotPort) -or
                                    $dotPort -lt 1 -or $dotPort -gt 65535) {
                                    $reason = "The DoT host must be a hostname and valid port, or the documented default ':' value."
                                }
                            }
                        }
                    }
                    foreach ($booleanOption in @("autoupgrade", "udpfallback")) {
                        if ($null -eq $reason -and $tokens.Contains($booleanOption) -and $tokens[$booleanOption].ToLowerInvariant() -notin @("yes", "no")) {
                            $reason = "The encryption command contains an unsupported Boolean option."
                        }
                    }
                    if ($null -eq $reason) {
                        $encryptionCommands += [pscustomobject]@{
                            lineNumber = $lineNumber
                            verb = $verb
                            server = [string]$tokens["server"]
                            dohTemplate = if ($tokens.Contains("dohtemplate")) { [string]$tokens["dohtemplate"] } else { $null }
                            dotHost = if ($tokens.Contains("dothost")) { [string]$tokens["dothost"] } else { $null }
                            autoUpgrade = if ($tokens.Contains("autoupgrade")) { $tokens["autoupgrade"].ToLowerInvariant() } else { $null }
                            udpFallback = if ($tokens.Contains("udpfallback")) { $tokens["udpfallback"].ToLowerInvariant() } else { $null }
                        }
                    }
                }
                "global" {
                    if ($tokens.Count -eq 0) {
                        $reason = "The global command contains no supported settings."
                    }
                    elseif ($tokens.Contains("doh") -and $tokens["doh"].ToLowerInvariant() -notin @("yes", "no", "auto")) {
                        $reason = "The global DoH value is unsupported."
                    }
                    elseif (($tokens.Contains("dot") -and $tokens["dot"].ToLowerInvariant() -notin @("yes", "no")) -or
                        ($tokens.Contains("ddr") -and $tokens["ddr"].ToLowerInvariant() -notin @("yes", "no"))) {
                        $reason = "The global DoT or DDR value is unsupported."
                    }
                    if ($null -eq $reason) {
                        $globalCommands += [pscustomobject]@{
                            lineNumber = $lineNumber
                            verb = $verb
                            doh = if ($tokens.Contains("doh")) { $tokens["doh"].ToLowerInvariant() } else { $null }
                            dot = if ($tokens.Contains("dot")) { $tokens["dot"].ToLowerInvariant() } else { $null }
                            ddr = if ($tokens.Contains("ddr")) { $tokens["ddr"].ToLowerInvariant() } else { $null }
                        }
                    }
                }
                "interface" {
                    if ([string]::IsNullOrWhiteSpace($alias)) {
                        $reason = "The interface command is missing its interface name."
                    }
                    elseif (-not $tokens.Contains("ddr") -and -not $tokens.Contains("ddrfallback")) {
                        $reason = "The interface command contains no supported DDR settings."
                    }
                    elseif (($tokens.Contains("ddr") -and $tokens["ddr"].ToLowerInvariant() -notin @("yes", "no")) -or
                        ($tokens.Contains("ddrfallback") -and $tokens["ddrfallback"].ToLowerInvariant() -notin @("yes", "no"))) {
                        $reason = "The interface DDR setting is unsupported."
                    }
                    if ($null -eq $reason) {
                        $interfaceCommands += [pscustomobject]@{
                            lineNumber = $lineNumber
                            verb = $verb
                            interfaceAlias = $alias
                            ddr = if ($tokens.Contains("ddr")) { $tokens["ddr"].ToLowerInvariant() } else { $null }
                            ddrFallback = if ($tokens.Contains("ddrfallback")) { $tokens["ddrfallback"].ToLowerInvariant() } else { $null }
                        }
                    }
                }
            }
        }

        if ($null -ne $reason) {
            $malformedStatements += [pscustomobject]@{
                lineNumber = $lineNumber
                verb = $verb
                section = $section
                interfaceAlias = $alias
                reason = $reason
            }
        }
        else {
            $recognizedCommandCount++
        }
    }

    $parseState = "unknown"
    if ($recognizedCommandCount -gt 0 -and $malformedStatements.Count -eq 0 -and $unsupportedStatements.Count -eq 0) {
        $parseState = "parsed"
    }
    elseif ($recognizedCommandCount -gt 0 -or $malformedStatements.Count -gt 0 -or $unsupportedStatements.Count -gt 0) {
        $parseState = "incomplete"
    }

    return [pscustomobject]@{
        parserSchemaVersion = 1
        parseState = $parseState
        recognizedCommandCount = $recognizedCommandCount
        malformedCommandCount = $malformedStatements.Count
        unsupportedCommandCount = $unsupportedStatements.Count
        dnsServerCommands = @($dnsServerCommands)
        encryptionCommands = @($encryptionCommands)
        globalCommands = @($globalCommands)
        interfaceCommands = @($interfaceCommands)
        malformedStatements = @($malformedStatements)
        unsupportedStatements = @($unsupportedStatements)
        limitation = "Only documented set/add command forms are parsed. A parsed result does not prove complete per-interface/profile/family state, stable adapter identity, or a supported DNS restore contract; absent statement families are not inferred to be default."
    }
}

Export-ModuleMember -Function ConvertTo-DnsAddressFamilyLabel, ConvertFrom-NetshInterfaceDnsDump, Get-NetshInterfaceDnsSourceForAdapter, ConvertFrom-NetshIPv6InterfaceDump, Get-NetshIPv6InterfaceDnsPolicyForAdapter, ConvertFrom-NetshDnsClientDump
)
                                $dotPort = 0
                                if (-not $dotHostMatch.Success -or
                                    -not [int]::TryParse([string]$dotHostMatch.Groups["port"].Value, [ref]$dotPort) -or
                                    $dotPort -lt 1 -or $dotPort -gt 65535) {
                                    $reason = "The DoT host must be a hostname and valid port, or the documented default ':' value."
                                }
                            }
                        }
                    }
                    foreach ($booleanOption in @("autoupgrade", "udpfallback")) {
                        if ($null -eq $reason -and $tokens.Contains($booleanOption) -and $tokens[$booleanOption].ToLowerInvariant() -notin @("yes", "no")) {
                            $reason = "The encryption command contains an unsupported Boolean option."
                        }
                    }
                    if ($null -eq $reason) {
                        $encryptionCommands += [pscustomobject]@{
                            lineNumber = $lineNumber
                            verb = $verb
                            server = [string]$tokens["server"]
                            dohTemplate = if ($tokens.Contains("dohtemplate")) { [string]$tokens["dohtemplate"] } else { $null }
                            dotHost = if ($tokens.Contains("dothost")) { [string]$tokens["dothost"] } else { $null }
                            autoUpgrade = if ($tokens.Contains("autoupgrade")) { $tokens["autoupgrade"].ToLowerInvariant() } else { $null }
                            udpFallback = if ($tokens.Contains("udpfallback")) { $tokens["udpfallback"].ToLowerInvariant() } else { $null }
                        }
                    }
                }
                "global" {
                    if ($tokens.Count -eq 0) {
                        $reason = "The global command contains no supported settings."
                    }
                    elseif ($tokens.Contains("doh") -and $tokens["doh"].ToLowerInvariant() -notin @("yes", "no", "auto")) {
                        $reason = "The global DoH value is unsupported."
                    }
                    elseif (($tokens.Contains("dot") -and $tokens["dot"].ToLowerInvariant() -notin @("yes", "no")) -or
                        ($tokens.Contains("ddr") -and $tokens["ddr"].ToLowerInvariant() -notin @("yes", "no"))) {
                        $reason = "The global DoT or DDR value is unsupported."
                    }
                    if ($null -eq $reason) {
                        $globalCommands += [pscustomobject]@{
                            lineNumber = $lineNumber
                            verb = $verb
                            doh = if ($tokens.Contains("doh")) { $tokens["doh"].ToLowerInvariant() } else { $null }
                            dot = if ($tokens.Contains("dot")) { $tokens["dot"].ToLowerInvariant() } else { $null }
                            ddr = if ($tokens.Contains("ddr")) { $tokens["ddr"].ToLowerInvariant() } else { $null }
                        }
                    }
                }
                "interface" {
                    if ([string]::IsNullOrWhiteSpace($alias)) {
                        $reason = "The interface command is missing its interface name."
                    }
                    elseif (-not $tokens.Contains("ddr") -and -not $tokens.Contains("ddrfallback")) {
                        $reason = "The interface command contains no supported DDR settings."
                    }
                    elseif (($tokens.Contains("ddr") -and $tokens["ddr"].ToLowerInvariant() -notin @("yes", "no")) -or
                        ($tokens.Contains("ddrfallback") -and $tokens["ddrfallback"].ToLowerInvariant() -notin @("yes", "no"))) {
                        $reason = "The interface DDR setting is unsupported."
                    }
                    if ($null -eq $reason) {
                        $interfaceCommands += [pscustomobject]@{
                            lineNumber = $lineNumber
                            verb = $verb
                            interfaceAlias = $alias
                            ddr = if ($tokens.Contains("ddr")) { $tokens["ddr"].ToLowerInvariant() } else { $null }
                            ddrFallback = if ($tokens.Contains("ddrfallback")) { $tokens["ddrfallback"].ToLowerInvariant() } else { $null }
                        }
                    }
                }
            }
        }

        if ($null -ne $reason) {
            $malformedStatements += [pscustomobject]@{
                lineNumber = $lineNumber
                verb = $verb
                section = $section
                interfaceAlias = $alias
                reason = $reason
            }
        }
        else {
            $recognizedCommandCount++
        }
    }

    $parseState = "unknown"
    if ($recognizedCommandCount -gt 0 -and $malformedStatements.Count -eq 0 -and $unsupportedStatements.Count -eq 0) {
        $parseState = "parsed"
    }
    elseif ($recognizedCommandCount -gt 0 -or $malformedStatements.Count -gt 0 -or $unsupportedStatements.Count -gt 0) {
        $parseState = "incomplete"
    }

    return [pscustomobject]@{
        parserSchemaVersion = 1
        parseState = $parseState
        recognizedCommandCount = $recognizedCommandCount
        malformedCommandCount = $malformedStatements.Count
        unsupportedCommandCount = $unsupportedStatements.Count
        dnsServerCommands = @($dnsServerCommands)
        encryptionCommands = @($encryptionCommands)
        globalCommands = @($globalCommands)
        interfaceCommands = @($interfaceCommands)
        malformedStatements = @($malformedStatements)
        unsupportedStatements = @($unsupportedStatements)
        limitation = "Only documented set/add command forms are parsed. A parsed result does not prove complete per-interface/profile/family state, stable adapter identity, or a supported DNS restore contract; absent statement families are not inferred to be default."
    }
}

Export-ModuleMember -Function ConvertTo-DnsAddressFamilyLabel, ConvertFrom-NetshInterfaceDnsDump, Get-NetshInterfaceDnsSourceForAdapter, ConvertFrom-NetshIPv6InterfaceDump, Get-NetshIPv6InterfaceDnsPolicyForAdapter, ConvertFrom-NetshDnsClientDump
