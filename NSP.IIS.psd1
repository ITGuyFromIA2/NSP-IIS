@{
    RootModule = 'NSP.IIS.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'f568c819-563a-4181-be85-a665779270d9'
    Author = 'Network Systems Plus'
    CompanyName = 'Network Systems Plus'
    Copyright = '(c) Network Systems Plus. All rights reserved.'
    Description = 'IIS from PowerShell: list site bindings with the certificate each one uses, find the bindings a new certificate should replace, repoint https bindings to a certificate, and list the http.sys SSL bindings outside IIS. Windows PowerShell 5.1 compatible; no WebAdministration module needed.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Test-NSPIisInstalled'
        'Get-NSPIisBinding'
        'Set-NSPIisBindingCertificate'
        'Get-NSPHttpSysSslBinding'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('NSP', 'IIS', 'Binding', 'SSL', 'TLS', 'Certificate', 'HttpSys', 'Windows')
            ProjectUri = 'https://github.com/ITGuyFromIA2/NSP-IIS'
            LicenseUri = 'https://github.com/ITGuyFromIA2/NSP-IIS/blob/main/LICENSE'
            ReleaseNotes = '0.1.0: first release - IIS bindings and their certificates, rebinding, http.sys SSL bindings.'
        }
    }
}
