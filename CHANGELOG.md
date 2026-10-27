# Changelog

## 0.1.0 (unreleased)

- First release. These commands go through `Microsoft.Web.Administration`, with no
  WebAdministration module:
  - `Get-NSPIisBinding`: site bindings and their certificates. `-Certificate` shows which bindings
    a new certificate should replace (host name on the certificate, or same names as the current
    certificate).
  - `Set-NSPIisBindingCertificate`: repoints https bindings, with `-WhatIf`.
  - `Test-NSPIisInstalled`.
- `Get-NSPHttpSysSslBinding`: http.sys SSL bindings from the registry, IIS's and everything else's.
