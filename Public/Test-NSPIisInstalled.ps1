function Test-NSPIisInstalled {
    <#
    .SYNOPSIS
        Whether IIS (the W3SVC service and its management API) is installed on this machine.
    .DESCRIPTION
        True when the World Wide Web Publishing Service exists and Microsoft.Web.Administration.dll
        is in inetsrv - what Get-NSPIisBinding and Set-NSPIisBindingCertificate need. Doesn't need
        elevation, so a caller can check before offering IIS steps.
    .EXAMPLE
        if (Test-NSPIisInstalled) { Get-NSPIisBinding }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $service = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    [bool]$service -and (Test-Path -LiteralPath (Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'))
}
