function Set-NSPIisBindingCertificate {
    <#
    .SYNOPSIS
        Points IIS https bindings at a certificate in LocalMachine\My (or another LocalMachine store).
    .DESCRIPTION
        Takes bindings by SiteName and BindingInformation, typically piped from Get-NSPIisBinding.
        The certificate must be in the store with its private key. IIS writes the change to http.sys
        as it does from IIS Manager; the site keeps running.

        One row per binding: SiteName, BindingInformation, PreviousThumbprint, Thumbprint, and Action
        (Updated, AlreadySet, WhatIf).
    .PARAMETER SiteName
        The site.
    .PARAMETER BindingInformation
        The binding, as ip:port:host (for example *:443:www.contoso.com).
    .PARAMETER Thumbprint
        The certificate to use.
    .PARAMETER StoreName
        The LocalMachine store holding it: My (default) or WebHosting.
    .EXAMPLE
        Set-NSPIisBindingCertificate -SiteName 'Default Web Site' -BindingInformation '*:443:' -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567
    .EXAMPLE
        Get-NSPIisBinding -Certificate $new | Where-Object Match | Set-NSPIisBindingCertificate -Thumbprint $new.Thumbprint
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][string]$SiteName,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][string]$BindingInformation,
        [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint,
        [ValidateSet('My', 'WebHosting')][string]$StoreName = 'My'
    )

    begin {
        $Thumbprint = $Thumbprint.ToUpperInvariant()
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, 'LocalMachine'
        try {
            $store.Open('ReadOnly')
            $certificate = @($store.Certificates.Find('FindByThumbprint', $Thumbprint, $false))[0]
        } finally {
            $store.Close()
        }
        if (-not $certificate) { throw "Certificate $Thumbprint isn't in LocalMachine\$StoreName." }
        if (-not $certificate.HasPrivateKey) { throw "Certificate $Thumbprint in LocalMachine\$StoreName has no private key." }
        $hash = [byte[]]::new(20)
        for ($i = 0; $i -lt 20; $i++) { $hash[$i] = [Convert]::ToByte($Thumbprint.Substring($i * 2, 2), 16) }
    }

    process {
        $manager = Get-NSPIisServerManager
        try {
            $site = $manager.Sites[$SiteName]
            if (-not $site) { throw "IIS has no site named '$SiteName'." }
            $binding = $site.Bindings | Where-Object { $_.Protocol -eq 'https' -and $_.BindingInformation -eq $BindingInformation } | Select-Object -First 1
            if (-not $binding) { throw "Site '$SiteName' has no https binding $BindingInformation." }
            $previous = if ($binding.CertificateHash) { ([BitConverter]::ToString([byte[]]$binding.CertificateHash) -replace '-', '').ToUpperInvariant() } else { '' }
            $row = [pscustomobject]@{
                SiteName           = $SiteName
                BindingInformation = $BindingInformation
                PreviousThumbprint = $previous
                Thumbprint         = $Thumbprint
                Action             = ''
            }
            if ($previous -eq $Thumbprint -and $binding.CertificateStoreName -eq $StoreName) {
                $row.Action = 'AlreadySet'
            } elseif ($PSCmdlet.ShouldProcess("$SiteName $BindingInformation", "Use certificate $Thumbprint ($($certificate.Subject))")) {
                $binding.CertificateHash = $hash
                $binding.CertificateStoreName = $StoreName
                $manager.CommitChanges()
                $row.Action = 'Updated'
            } else {
                $row.Action = 'WhatIf'
            }
            $row
        } finally {
            $manager.Dispose()
        }
    }
}
