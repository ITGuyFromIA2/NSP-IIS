function Get-NSPHttpSysSslBinding {
    <#
    .SYNOPSIS
        Lists the http.sys SSL bindings (what netsh http show sslcert shows): IIS's and everything
        else's - RD Gateway, WinRM over HTTPS, ADFS, Exchange, vendor web consoles.
    .DESCRIPTION
        Read from the registry http.sys keeps them in, so the output doesn't depend on netsh's
        language. One row per binding: Kind (IpPort, HostnamePort, CentralStore), Endpoint, Thumbprint,
        StoreName, AppId, and Owner (IIS for IIS's application ID, otherwise the AppId).

        Useful before removing an old certificate: anything still listed with its thumbprint stops
        working when it's gone.
    .PARAMETER Thumbprint
        Only bindings using this certificate.
    .PARAMETER ExcludeIis
        Leave out IIS's own bindings (Get-NSPIisBinding reports those with their site).
    .EXAMPLE
        Get-NSPHttpSysSslBinding -ExcludeIis
    .EXAMPLE
        Get-NSPHttpSysSslBinding -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint,
        [switch]$ExcludeIis
    )

    $iisAppId = '4dc3e181-e14b-4a21-b022-59fc669b0914'
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
    $toHex = { param($Value) if ($Value -is [byte[]] -and $Value.Length) { ([BitConverter]::ToString($Value) -replace '-', '').ToUpperInvariant() } else { '' } }
    foreach ($kind in @(@('SslBindingInfo', 'IpPort'), @('SslSniBindingInfo', 'HostnamePort'), @('SslCcsBindingInfo', 'CentralStore'))) {
        foreach ($key in @(Get-ChildItem -LiteralPath "$base\$($kind[0])" -ErrorAction SilentlyContinue)) {
            $values = Get-ItemProperty -LiteralPath $key.PSPath
            $hash = & $toHex $values.SslCertHash
            if ($Thumbprint -and $hash -ne $Thumbprint.ToUpperInvariant()) { continue }
            $appId = if ($values.AppId -is [byte[]] -and $values.AppId.Length -eq 16) { ([guid]::new([byte[]]$values.AppId)).ToString() } else { ([string]$values.AppId).Trim('{}').ToLowerInvariant() }
            $owner = if ($appId -eq $iisAppId) { 'IIS' } else { $appId }
            if ($ExcludeIis -and $owner -eq 'IIS') { continue }
            [pscustomobject]@{
                Kind       = $kind[1]
                Endpoint   = $key.PSChildName
                Thumbprint = $hash
                StoreName  = [string]$values.SslCertStoreName
                AppId      = $appId
                Owner      = $owner
            }
        }
    }
}
