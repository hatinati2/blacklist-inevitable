Set-StrictMode -Version Latest

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

Export-ModuleMember -Function ConvertFrom-NetshInterfaceDnsDump, Get-NetshInterfaceDnsSourceForAdapter
