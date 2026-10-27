# NSP.IIS

IIS from PowerShell, for NSP tools and scripts. Windows PowerShell **5.1** compatible. It reads and
changes IIS through `Microsoft.Web.Administration` (inetsrv), the API IIS Manager uses, so the
WebAdministration module and its `IIS:` drive aren't needed. It has no NSP dependencies.

| Function | Purpose |
|---|---|
| `Test-NSPIisInstalled` | Whether IIS is installed (W3SVC plus its management API). Needs no elevation. |
| `Get-NSPIisBinding` | Site bindings with the certificate each https binding uses. `-Certificate` adds `Match`/`MatchReason`. |
| `Set-NSPIisBindingCertificate` | Points https bindings at a certificate in `LocalMachine\My`. Takes pipeline input, supports `-WhatIf`. |
| `Get-NSPHttpSysSslBinding` | Every http.sys SSL binding, including those outside IIS (RD Gateway, WinRM, ADFS...). Read from the registry, so it's language-independent. |

## Replacing a certificate

```powershell
$new = Get-Item Cert:\LocalMachine\My\<thumbprint>
Get-NSPIisBinding -Certificate $new | Format-Table SiteName, BindingInformation, CertificateSubject, Match, MatchReason
Get-NSPIisBinding -Certificate $new | Where-Object Match | Set-NSPIisBindingCertificate -Thumbprint $new.Thumbprint -WhatIf
```

How `-Certificate` decides which bindings match:

| Binding | Matches when |
|---|---|
| Has a host name (SNI or host header) | The host name is on the certificate. A wildcard covers exactly one label. |
| No host name (`*:443:`, `10.0.0.5:443:`) | Its current certificate covers one of the same names, which is the renewal case. |

Bindings that never match, each with its reason: already on the certificate, no certificate,
current certificate missing from the store, Central Certificate Store, not https.

NSP.SSLCertificates' `Install-NSPSslCertificate` uses this to offer the rebind after an import.

## Before removing an old certificate

```powershell
Get-NSPIisBinding | Where-Object Thumbprint -eq $oldThumbprint
Get-NSPHttpSysSslBinding -Thumbprint $oldThumbprint -ExcludeIis
```

Both must come back empty. Services that load a certificate by thumbprint without http.sys (RDP
listener, SQL Server, LDAPS, Exchange's own config) aren't covered.

## Notes

- Run elevated. IIS's configuration is readable by administrators only.
- PowerShell 7 loads the inetsrv assembly too. If it won't on a host, use Windows PowerShell 5.1.

## Tests

```powershell
.\tools\Test-Repo.ps1   # manifest, help, smoke checks under 5.1 and pwsh, PSScriptAnalyzer
```

The smoke test covers the binding parsing and matching with throwaway certificates, and needs no
IIS. Rebinding against a real IIS isn't covered by the automated tests.
