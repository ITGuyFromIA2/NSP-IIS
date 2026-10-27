@{
    IncludeDefaultRules = $true
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # Fires on private helpers that only build rows; the public command that changes a binding
        # declares SupportsShouldProcess.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
