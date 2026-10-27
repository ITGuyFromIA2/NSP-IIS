function Test-NSPIisHostMatch {
    # Whether a host name is covered by any of a certificate's DNS names. A wildcard covers exactly
    # one label: *.contoso.com covers vpn.contoso.com, not contoso.com or a.b.contoso.com.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$HostName,
        [AllowEmptyCollection()][string[]]$Name = @()
    )

    $hostName = $HostName.Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $hostName) { return $false }
    foreach ($candidate in $Name) {
        $candidate = $candidate.ToLowerInvariant()
        if ($candidate -eq $hostName) { return $true }
        if ($candidate.StartsWith('*.')) {
            $dot = $hostName.IndexOf('.')
            if ($dot -gt 0 -and $hostName.Substring($dot + 1) -eq $candidate.Substring(2)) { return $true }
        }
    }
    $false
}
