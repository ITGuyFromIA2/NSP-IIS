function ConvertTo-NSPIisBindingRow {
    # One binding as a row, from plain values so it can be tested without IIS. With Certificate,
    # Match says whether that certificate should replace the binding's current one, and MatchReason
    # why (or why not):
    #   a host name binding (SNI, or a host header on a shared IP) matches when the host name is on
    #   the certificate; a binding without a host name matches when its current certificate covers
    #   one of the same names - the renewal case.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$SiteName,
        [long]$SiteId,
        [string]$SiteState,
        [Parameter(Mandatory)][string]$Protocol,
        [Parameter(Mandatory)][AllowEmptyString()][string]$BindingInformation,
        [AllowNull()][byte[]]$CertificateHash,
        [AllowEmptyString()][string]$CertificateStoreName,
        [int]$SslFlags,
        [AllowNull()][System.Security.Cryptography.X509Certificates.X509Certificate2]$CurrentCertificate,
        [AllowNull()][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # ip:port:host - the IP may be an IPv6 literal in brackets, so split from the right.
    $ipAddress = ''; $port = 0; $hostName = ''
    if ($BindingInformation -match '^(?<ip>.*):(?<port>\d+):(?<host>[^:]*)$') {
        $ipAddress = $Matches.ip; $port = [int]$Matches.port; $hostName = $Matches.host
    }
    $thumbprint = if ($CertificateHash -and $CertificateHash.Length) { ([BitConverter]::ToString($CertificateHash) -replace '-', '').ToUpperInvariant() } else { '' }
    $currentNames = @(if ($CurrentCertificate) { Get-NSPIisDnsName -Certificate $CurrentCertificate })

    $row = [pscustomobject]@{
        SiteName            = $SiteName
        SiteId              = $SiteId
        SiteState           = $SiteState
        Protocol            = $Protocol
        BindingInformation  = $BindingInformation
        IPAddress           = $ipAddress
        Port                = $port
        HostName            = $hostName
        Sni                 = [bool]($SslFlags -band 1)
        CentralCertStore    = [bool]($SslFlags -band 2)
        Thumbprint          = $thumbprint
        StoreName           = $CertificateStoreName
        CertificateFound    = [bool]$CurrentCertificate
        CertificateSubject  = $(if ($CurrentCertificate) { $CurrentCertificate.Subject } else { '' })
        CertificateNotAfter = $(if ($CurrentCertificate) { $CurrentCertificate.NotAfter } else { $null })
        CertificateNames    = $currentNames
        Match               = $null
        MatchReason         = ''
    }
    if (-not $Certificate) { return $row }

    $names = @(Get-NSPIisDnsName -Certificate $Certificate)
    $match = $false
    $reason = if ($Protocol -ne 'https') {
        'Not an https binding'
    } elseif ($row.CentralCertStore) {
        'Uses the Central Certificate Store'
    } elseif ($thumbprint -eq $Certificate.Thumbprint.ToUpperInvariant()) {
        'Already uses this certificate'
    } elseif ($hostName) {
        if (Test-NSPIisHostMatch -HostName $hostName -Name $names) { $match = $true; "Host name $hostName is on the certificate" }
        else { "Host name $hostName is not on the certificate" }
    } elseif (-not $thumbprint) {
        'No certificate bound'
    } elseif (-not $CurrentCertificate) {
        'Current certificate is not in the store'
    } elseif (@($currentNames | Where-Object { $_ -in $names }).Count) {
        $match = $true
        'Current certificate covers the same names'
    } else {
        'Current certificate is for other names'
    }
    $row.Match = $match
    $row.MatchReason = $reason
    $row
}
