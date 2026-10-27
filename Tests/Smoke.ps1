$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'NSP.IIS.psd1') -Force
$module = Get-Module NSP.IIS

function Assert-Equal($Actual, $Expected, $Message) {
    if ($Actual -ne $Expected) { throw "$Message. Expected '$Expected', got '$Actual'." }
}
function Assert-Error([scriptblock]$Script, [string]$Pattern, [string]$Message) {
    try { & $Script } catch { if ($_.Exception.Message -match $Pattern) { return }; throw "$Message. Wrong error: $($_.Exception.Message)" }
    throw "$Message. Expected an error."
}

$x509 = 'System.Security.Cryptography.X509Certificates'
$now = [DateTimeOffset]::Now
# A throwaway self-signed certificate for these names (never stored).
function New-TestCertificate([string[]]$Names) {
    $key = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
    $key.PersistKeyInCsp = $false
    $request = New-Object "$x509.CertificateRequest"("CN=$($Names[0])", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $san = New-Object "$x509.SubjectAlternativeNameBuilder"
    foreach ($name in $Names) { $san.AddDnsName($name) }
    $request.CertificateExtensions.Add($san.Build())
    $request.CreateSelfSigned($now.AddDays(-1), $now.AddDays(90))
}
$row = { param([hashtable]$Values) & $module { param($v) ConvertTo-NSPIisBindingRow @v } $Values }
$hashOf = { param($Certificate) $Certificate.GetCertHash() }

# Host names: exact, case-insensitive, wildcard covers exactly one label.
$hostMatch = { param($HostName, $Names) & $module { param($h, $n) Test-NSPIisHostMatch -HostName $h -Name $n } $HostName $Names }
Assert-Equal (& $hostMatch 'VPN.contoso.com' @('vpn.contoso.com')) $true 'Exact host, any case'
Assert-Equal (& $hostMatch 'vpn.contoso.com' @('*.contoso.com')) $true 'Wildcard covers one label'
Assert-Equal (& $hostMatch 'contoso.com' @('*.contoso.com')) $false 'Wildcard does not cover the apex'
Assert-Equal (& $hostMatch 'a.b.contoso.com' @('*.contoso.com')) $false 'Wildcard does not cover two labels'
Assert-Equal (& $hostMatch '' @('vpn.contoso.com')) $false 'Empty host never matches'

$new = New-TestCertificate 'portal.contoso.com', 'www.contoso.com'
$old = New-TestCertificate 'portal.contoso.com'
$other = New-TestCertificate 'intranet.fabrikam.com'
$base = @{ SiteName = 'Default Web Site'; SiteId = 1; SiteState = 'Started'; Protocol = 'https' }

# Parsing: IPv4, IPv6 in brackets, host header; SNI and CCS flags.
$parsed = & $row ($base + @{ BindingInformation = '[2001:db8::1]:8443:www.contoso.com'; SslFlags = 1 })
Assert-Equal "$($parsed.IPAddress)|$($parsed.Port)|$($parsed.HostName)|$($parsed.Sni)" '[2001:db8::1]|8443|www.contoso.com|True' 'IPv6 binding parsed'
Assert-Equal $parsed.Match $null 'No Match column without -Certificate'

# Matching against the new certificate.
$cases = @(
    ,@(@{ BindingInformation = '*:443:'; CertificateHash = (& $hashOf $old); CertificateStoreName = 'My'; CurrentCertificate = $old }, $true, 'same names')
    ,@(@{ BindingInformation = '*:443:'; CertificateHash = (& $hashOf $other); CertificateStoreName = 'My'; CurrentCertificate = $other }, $false, 'other names')
    ,@(@{ BindingInformation = '*:443:www.contoso.com'; SslFlags = 1; CertificateHash = (& $hashOf $other); CurrentCertificate = $other }, $true, 'is on the certificate')
    ,@(@{ BindingInformation = '*:443:shop.contoso.com'; SslFlags = 1 }, $false, 'is not on the certificate')
    ,@(@{ BindingInformation = '*:443:'; CertificateHash = (& $hashOf $new); CurrentCertificate = $new }, $false, 'Already uses')
    ,@(@{ BindingInformation = '*:443:'; CertificateHash = (& $hashOf $old) }, $false, 'not in the store')
    ,@(@{ BindingInformation = '*:443:'; }, $false, 'No certificate')
    ,@(@{ BindingInformation = '*:443:portal.contoso.com'; SslFlags = 3 }, $false, 'Central Certificate Store')
    ,@(@{ BindingInformation = '*:80:portal.contoso.com'; Protocol = 'http' }, $false, 'Not an https')
)
foreach ($case in $cases) {
    $values = $base.Clone()
    foreach ($key in $case[0].Keys) { $values[$key] = $case[0][$key] }
    $values.Certificate = $new
    $result = & $row $values
    Assert-Equal $result.Match $case[1] "Match for $($values.BindingInformation) ($($case[2]))"
    Assert-Equal ($result.MatchReason -match $case[2]) $true "Reason for $($values.BindingInformation): $($result.MatchReason)"
}
$renewal = & $row ($base + @{ BindingInformation = '*:443:'; CertificateHash = (& $hashOf $old); CertificateStoreName = 'My'; CurrentCertificate = $old; Certificate = $new })
Assert-Equal $renewal.Thumbprint $old.Thumbprint 'Current thumbprint from the hash'
Assert-Equal ($renewal.CertificateNames -join ',') 'portal.contoso.com' 'Current certificate names'

# Commands that need IIS fail plainly without it; the http.sys listing never needs it.
Assert-Equal ((Test-NSPIisInstalled) -is [bool]) $true 'Test-NSPIisInstalled returns a bool'
if (-not (Test-NSPIisInstalled)) {
    Assert-Error { Get-NSPIisBinding } "IIS isn't installed" 'Get-NSPIisBinding without IIS'
}
$null = @(Get-NSPHttpSysSslBinding)
Assert-Error { Get-NSPHttpSysSslBinding -Thumbprint 'xyz' } 'does not match|pattern' 'Thumbprint validated'

'NSP.IIS smoke checks passed.'
