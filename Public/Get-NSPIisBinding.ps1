function Get-NSPIisBinding {
    <#
    .SYNOPSIS
        Lists IIS site bindings with the certificate each https binding uses; with -Certificate, also
        which of them that certificate should replace.
    .DESCRIPTION
        One row per binding: SiteName, SiteId, SiteState, Protocol, BindingInformation (ip:port:host),
        IPAddress, Port, HostName, Sni, CentralCertStore, Thumbprint, StoreName, and the current
        certificate as found in LocalMachine\<StoreName>: CertificateFound, CertificateSubject,
        CertificateNotAfter, CertificateNames.

        With -Certificate, Match and MatchReason say whether the certificate belongs on the binding:

            host name binding      the host name is on the certificate (wildcards cover one label)
            no host name           the current certificate covers one of the same names (a renewal)

        Bindings already on the certificate, without a certificate, on the Central Certificate
        Store, or whose current certificate is missing from the store don't match; MatchReason
        says which.

        Reads IIS through Microsoft.Web.Administration (inetsrv), as IIS Manager does; the
        WebAdministration module isn't needed. Run elevated: IIS's configuration is readable by
        administrators only.
    .PARAMETER SiteName
        Only these sites. All sites by default.
    .PARAMETER Protocol
        https (default), http, or All.
    .PARAMETER Certificate
        A certificate to match the bindings against (for example the one just imported).
    .EXAMPLE
        Get-NSPIisBinding | Format-Table SiteName, BindingInformation, CertificateSubject, CertificateNotAfter
    .EXAMPLE
        $new = Get-Item Cert:\LocalMachine\My\<thumbprint>
        Get-NSPIisBinding -Certificate $new | Where-Object Match | Set-NSPIisBindingCertificate -Thumbprint $new.Thumbprint -WhatIf
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string[]]$SiteName,
        [ValidateSet('https', 'http', 'All')][string]$Protocol = 'https',
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $stores = @{}
    $findCertificate = {
        param([string]$StoreName, [string]$Thumbprint)
        if (-not $Thumbprint) { return $null }
        if (-not $StoreName) { $StoreName = 'My' }
        if (-not $stores.ContainsKey($StoreName)) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, 'LocalMachine'
            try {
                $store.Open('ReadOnly')
                $stores[$StoreName] = @($store.Certificates)
            } catch {
                $stores[$StoreName] = @()
            } finally {
                $store.Close()
            }
        }
        $stores[$StoreName] | Where-Object Thumbprint -EQ $Thumbprint | Select-Object -First 1
    }

    $manager = Get-NSPIisServerManager
    try {
        foreach ($site in $manager.Sites) {
            if ($SiteName -and $site.Name -notin $SiteName) { continue }
            $state = try { [string]$site.State } catch { 'Unknown' }
            foreach ($binding in $site.Bindings) {
                if ($Protocol -ne 'All' -and $binding.Protocol -ne $Protocol) { continue }
                $hash = [byte[]]$binding.CertificateHash
                $thumbprint = if ($hash) { ([BitConverter]::ToString($hash) -replace '-', '').ToUpperInvariant() } else { '' }
                $sslFlags = try { [int]$binding.SslFlags } catch { 0 }
                $row = @{
                    SiteName             = $site.Name
                    SiteId               = $site.Id
                    SiteState            = $state
                    Protocol             = $binding.Protocol
                    BindingInformation   = $binding.BindingInformation
                    CertificateHash      = $hash
                    CertificateStoreName = [string]$binding.CertificateStoreName
                    SslFlags             = $sslFlags
                    CurrentCertificate   = (& $findCertificate $binding.CertificateStoreName $thumbprint)
                    Certificate          = $Certificate
                }
                ConvertTo-NSPIisBindingRow @row
            }
        }
    } finally {
        $manager.Dispose()
    }
}
