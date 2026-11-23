#requires -Version 5.1
# Mocked servicing only: never execute the installer or Windows capability cmdlets.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sourcePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'support\windows-ssh.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput(
    [IO.File]::ReadAllText($sourcePath, [Text.Encoding]::UTF8), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors | Out-String) }
$definitions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Ensure-SupportOpenSshCapabilities'
}, $true))
if ($definitions.Count -ne 1) { throw 'Expected exactly one capability coordinator.' }
. ([scriptblock]::Create($definitions[0].Extent.Text))
$client = 'OpenSSH.Client~~~~0.0.1.0'
$server = 'OpenSSH.Server~~~~0.0.1.0'
$script:scenarios = 0

function Get-WindowsCapability {
    [CmdletBinding()]
    param([switch] $Online, [string] $Name)
    if (-not $Online -or $Name -cnotin @($client, $server)) { throw 'Unexpected capability query.' }
    $script:events.Add('Get:' + $Name)
    $sequence = $script:states[$Name]
    $index = [Math]::Min($script:reads[$Name], $sequence.Count - 1)
    $script:reads[$Name]++
    return [pscustomobject]@{ Name = $Name; State = $sequence[$index] }
}

function Add-WindowsCapability {
    [CmdletBinding()]
    param([switch] $Online, [string] $Name)
    if (-not $Online -or $Name -cnotin @($client, $server)) { throw 'Unexpected capability install.' }
    if ($ProgressPreference -ne 'Continue') { throw 'Install progress was not enabled.' }
    $script:events.Add('Add:' + $Name)
    $script:addCalls.Add($Name)
    return [pscustomobject]@{ RestartNeeded = $script:restartNeeded }
}

function Assert-Scenario {
    param([string] $Label, [string[]] $ClientStates, [string[]] $ServerStates,
        [string[]] $ExpectedAdds = @(), [string[]] $ErrorFragments = @(), [bool] $RestartNeeded = $false)
    $script:states = @{ $client = $ClientStates; $server = $ServerStates }
    $script:reads = @{ $client = 0; $server = 0 }
    $script:events = New-Object 'Collections.Generic.List[string]'
    $script:addCalls = New-Object 'Collections.Generic.List[string]'
    $script:restartNeeded = $RestartNeeded
    $attempted = $false
    $failure = $null
    try { Ensure-SupportOpenSshCapabilities -InstallAttempted ([ref]$attempted) 6>$null }
    catch { $failure = $_.Exception.Message }
    if (($script:addCalls -join '|') -cne ($ExpectedAdds -join '|')) {
        throw "$Label invoked an unexpected Add-WindowsCapability."
    }
    if ($attempted -ne ($ExpectedAdds.Count -gt 0)) { throw "$Label returned an incorrect installation-attempt flag." }
    if ($script:events.Count -lt 2 -or $script:events[0] -cne ('Get:' + $client) -or
        $script:events[1] -cne ('Get:' + $server)) { throw "$Label did not prequery both capabilities before any install." }
    if ($ErrorFragments.Count -eq 0) {
        if ($null -ne $failure) { throw "$Label failed unexpectedly: $failure" }
    } else {
        if ($null -eq $failure) { throw "$Label accepted an unusable capability state." }
        foreach ($fragment in $ErrorFragments) {
            if ($failure.IndexOf($fragment, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                throw "$Label did not explain the failing capability/state/action: $failure"
            }
        }
    }
    if ($ProgressPreference -ne 'SilentlyContinue') { throw "$Label failed to restore progress preference." }
    $script:scenarios++
}

foreach ($pending in @('InstallPending', 'UninstallPending', 'RemovePending')) {
    Assert-Scenario -Label ('Pending client ' + $pending) -ClientStates @($pending) -ServerStates @('NotPresent') `
        -ErrorFragments @($client, $pending, 'Restart Windows')
    Assert-Scenario -Label ('Absent client with pending server ' + $pending) -ClientStates @('NotPresent') -ServerStates @($pending) `
        -ErrorFragments @($server, $pending, 'Restart Windows')
    Assert-Scenario -Label ('Postinstall pending despite false restart ' + $pending) `
        -ClientStates @('Installed') -ServerStates @('NotPresent', 'NotPresent', $pending) `
        -ExpectedAdds @($server) -ErrorFragments @($server, $pending, 'Restart Windows')
}
Assert-Scenario -Label 'Both installed' -ClientStates @('Installed') -ServerStates @('Installed')
Assert-Scenario -Label 'Install server' -ClientStates @('Installed') `
    -ServerStates @('NotPresent', 'NotPresent', 'Installed') -ExpectedAdds @($server)
Assert-Scenario -Label 'Install both' -ClientStates @('NotPresent', 'NotPresent', 'Installed') `
    -ServerStates @('NotPresent', 'NotPresent', 'Installed') -ExpectedAdds @($client, $server)
Assert-Scenario -Label 'RestartRequired despite installed state' -ClientStates @('Installed') `
    -ServerStates @('NotPresent', 'NotPresent', 'Installed') -ExpectedAdds @($server) -RestartNeeded $true `
    -ErrorFragments @($server, 'Installed', 'Restart Windows')
Assert-Scenario -Label 'State changes before Add' -ClientStates @('Installed') `
    -ServerStates @('NotPresent', 'InstallPending') -ErrorFragments @($server, 'InstallPending', 'Restart Windows')
Assert-Scenario -Label 'State finishes before Add' -ClientStates @('Installed') `
    -ServerStates @('NotPresent', 'Installed')
foreach ($unsupported in @('Staged', 'Removed', 'Superseded', 'PartiallyInstalled', 'Unexpected', '')) {
    Assert-Scenario -Label ('Unsupported preflight ' + $unsupported) -ClientStates @('NotPresent') -ServerStates @($unsupported) `
        -ErrorFragments @($server, 'unsupported state')
}
Assert-Scenario -Label 'Unknown after Add' -ClientStates @('Installed') `
    -ServerStates @('NotPresent', 'NotPresent', 'Unexpected') -ExpectedAdds @($server) `
    -ErrorFragments @($server, 'Unexpected', "expected 'Installed'")
Assert-Scenario -Label 'Still absent after Add' -ClientStates @('Installed') `
    -ServerStates @('NotPresent') -ExpectedAdds @($server) -ErrorFragments @($server, 'NotPresent', "expected 'Installed'")
Write-Output ("PASS: {0} mocked capability scenarios on PowerShell {1}; no installer or real capability cmdlets executed." -f $script:scenarios, $PSVersionTable.PSVersion)
