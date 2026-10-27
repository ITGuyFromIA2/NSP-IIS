function Get-NSPIisServerManager {
    # A Microsoft.Web.Administration ServerManager, the API IIS Manager itself uses. Loaded from
    # inetsrv so the WebAdministration module (and its IIS: drive) isn't needed. Dispose it.
    [CmdletBinding()]
    param()

    $assembly = Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
    if (-not (Test-Path -LiteralPath $assembly)) { throw "IIS isn't installed on this machine ($assembly not found)." }
    if (-not ('Microsoft.Web.Administration.ServerManager' -as [type])) {
        try {
            Add-Type -Path $assembly -ErrorAction Stop
        } catch {
            throw "Could not load $assembly ($($_.Exception.Message)). Run this from Windows PowerShell 5.1."
        }
    }
    New-Object Microsoft.Web.Administration.ServerManager
}
