#requires -Version 5.1
# Offline fixtures only. Never dot-source or execute the support installer.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'support\windows-ssh.ps1'
$source = [IO.File]::ReadAllText($sourcePath, [Text.Encoding]::UTF8)
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors | Out-String) }
$definitions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -cin @('Resolve-LocalSupportUser', 'Invoke-SupportUtf8Process', 'Read-OwnedState')
}, $true))
if ($definitions.Count -ne 3) { throw 'Expected the account resolver, UTF8 capture helper and state reader.' }
# Define only the extracted functions; no bootstrap statements run. The native
# helper is invoked below with a harmless child, never the installer or sshd.
foreach ($definition in $definitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
$fixtureSid = 'S-1-5-21-111111111-222222222-333333333-1001'
$script:fixtures = 0

function New-AccountFixture {
    param([string] $Name = 'Seller', [AllowNull()] [object] $Source = 'Local',
        [string] $Sid = $fixtureSid, [bool] $Enabled = $true, [switch] $OmitSource)
    $record = [ordered]@{ Name = $Name; SID = $Sid; Enabled = $Enabled }
    if (-not $OmitSource) { $record.PrincipalSource = $Source }
    return [pscustomobject]$record
}

function Assert-Allowed([object[]] $Accounts, [string] $Expected, [string] $Label) {
    $actual = Resolve-LocalSupportUser -Accounts $Accounts -CurrentSid $fixtureSid
    if ($actual -cne $Expected) { throw "$Label returned an unexpected literal username." }
    $script:fixtures++
}

function Assert-Rejected([object[]] $Accounts, [string] $Label, [string] $CurrentSid = $fixtureSid) {
    $rejected = $false
    try { $null = Resolve-LocalSupportUser -Accounts $Accounts -CurrentSid $CurrentSid }
    catch { $rejected = $true }
    if (-not $rejected) { throw "$Label was accepted unexpectedly." }
    $script:fixtures++
}

Assert-Allowed @(New-AccountFixture) 'seller' 'Local source'
Assert-Allowed @(New-AccountFixture -Source $null) 'seller' 'Null source'
Assert-Allowed @(New-AccountFixture -Source '') 'seller' 'Empty source'
Assert-Allowed @(New-AccountFixture -OmitSource) 'seller' 'Absent source property'
Assert-Allowed @(New-AccountFixture -Source 'MicrosoftAccount') 'seller' 'Microsoft-connected local source'
Assert-Allowed @(New-AccountFixture -Name 'Seller Smith') 'seller smith' 'Literal space'
Assert-Allowed @(New-AccountFixture -Name "O'Brien") "o'brien" 'Literal apostrophe'
Assert-Allowed @(New-AccountFixture -Name 'Seller_2.A-B') 'seller_2.a-b' 'Safe punctuation'
$unicode = ([char]0x4E70).ToString() + ([char]0x5BB6).ToString() + ' Seller'
Assert-Allowed @(New-AccountFixture -Name $unicode) ($unicode.ToLowerInvariant()) 'Unicode letters'
$decomposed = 'Re' + [char]0x0301 + 'nee'
Assert-Allowed @(New-AccountFixture -Name $decomposed) ($decomposed.ToLowerInvariant()) 'Unicode combining mark preserved'
$nativeSidRecord = New-AccountFixture
$nativeSidRecord.SID = New-Object Security.Principal.SecurityIdentifier($fixtureSid)
Assert-Allowed @($nativeSidRecord) 'seller' 'Native SID object'

Assert-Rejected @() 'No matching local records'
Assert-Rejected @($null) 'Null record'
Assert-Rejected @((New-AccountFixture), (New-AccountFixture)) 'Ambiguous local records'
Assert-Rejected @(New-AccountFixture -Sid 'S-1-5-21-111111111-222222222-333333333-1002') 'SID mismatch'
Assert-Rejected @(New-AccountFixture) 'Missing current SID' ''
Assert-Rejected @(New-AccountFixture -Enabled $false) 'Disabled local user'
foreach ($sourceType in @('ActiveDirectory', 'AzureAD', 'MicrosoftEntra', 'Unknown')) {
    Assert-Rejected @(New-AccountFixture -Source $sourceType) ('Nonlocal source ' + $sourceType)
}
Assert-Rejected @([pscustomobject]@{ Name = 'Seller'; Enabled = $true }) 'Missing SID property'
Assert-Rejected @([pscustomobject]@{ Name = 'Seller'; SID = $fixtureSid }) 'Missing enabled property'
Assert-Rejected @([pscustomobject]@{ Name = 'Seller'; SID = $fixtureSid; Enabled = 'true' }) 'Nonboolean enabled value'
foreach ($name in @('', ' ', '...', ('a' * 21), 'seller*', 'seller?', '!seller', '[seller]',
    'seller@host', 'seller,other', 'domain\seller', 'domain/seller', 'seller"other',
    'seller`other', 'seller$other', 'seller;other', 'seller:other', 'seller#other',
    "seller`nAllowUsers *", "seller`rAllowUsers *", "seller`0other", "seller`tother")) {
    Assert-Rejected @(New-AccountFixture -Name $name) 'Unsafe username fixture'
}

# Exercise the actual UTF8 helper with a harmless Windows PowerShell child. A large
# stderr stream checks that both pipes drain while a Unicode username stays exact.
$childSource = @'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::Error.Write(('e' * 131072))
$name = ([char]0x4E70).ToString() + ([char]0x5BB6).ToString() + ' Smith'
[Console]::Out.WriteLine('allowusers ' + $name)
'@
$encodedChild = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childSource))
$windowsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$childExe = Join-Path $windowsDir 'System32\WindowsPowerShell\v1.0\powershell.exe'
$capture = Invoke-SupportUtf8Process $childExe ('-NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand ' + $encodedChild)
if ($capture.ExitCode -ne 0 -or -not $capture.StandardError.Contains(('e' * 131072)) -or
    @($capture.StandardOutput -split '\r?\n') -cnotcontains ('allowusers ' + $unicode.Replace('Seller', 'Smith'))) {
    throw 'Native UTF8 capture failed to preserve a Unicode username or drain both pipes.'
}

# Exercise the actual state reader on a UTF8-noBOM file, as written by the
# installer. This fixture isolates text decoding; ACL checking is stubbed only
# for this disposable directory and is not claimed as security validation.
$parentDir = Join-Path ([IO.Path]::GetTempPath()) ('wao-support-identity-' + [guid]::NewGuid().ToString('N'))
$stateDir = Join-Path $parentDir 'state'
$stateFile = Join-Path $stateDir 'state.json'
$ownedFiles = @('state.json')
$ownerTag = 'WAO.SellerSupport.Windows.v1'
function Assert-TrustedAcl([string] $Path) {
    if ($Path -cnotin @($parentDir, $stateDir, $stateFile) -or -not (Test-Path -LiteralPath $Path)) {
        throw 'State fixture attempted to inspect an unexpected path.'
    }
}
$fixtureState = [ordered]@{ owner = $ownerTag; schema = 1; machineId = [guid]::NewGuid().ToString()
    binding = [ordered]@{ localUser = $unicode.ToLowerInvariant(); userSid = $fixtureSid } }
try {
    $null = [IO.Directory]::CreateDirectory($stateDir)
    [IO.File]::WriteAllText($stateFile, ($fixtureState | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
    $roundTrip = Read-OwnedState
    if ($roundTrip.binding.localUser -cne $fixtureState.binding.localUser -or
        $roundTrip.binding.userSid -cne $fixtureSid) {
        throw 'Reading UTF8-noBOM state changed the exact Unicode account binding.'
    }
} finally {
    # Delete exactly these fixture items; never recursively delete a computed path.
    if (Test-Path -LiteralPath $stateFile) { Remove-Item -LiteralPath $stateFile }
    if (Test-Path -LiteralPath $stateDir) { Remove-Item -LiteralPath $stateDir }
    if (Test-Path -LiteralPath $parentDir) { Remove-Item -LiteralPath $parentDir }
}

# Parse both generated workers too, without evaluating their source.
$workers = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -in @('serverScript', 'tunnelScript')
}, $true))
if ($workers.Count -ne 2) { throw 'Expected two worker source literals.' }
foreach ($worker in $workers) {
    $literal = $worker.Right.Find({
        param($node)
        $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
    }, $false)
    if ($null -eq $literal) { throw 'Missing worker source literal.' }
    $workerTokens = $null
    $workerErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($literal.Value, [ref]$workerTokens, [ref]$workerErrors)
    if ($workerErrors.Count -gt 0) { throw ($workerErrors | Out-String) }
}
Write-Output ("PASS: {0} account fixtures, native UTF8/dual-pipe fixture and Unicode state roundtrip; bootstrap and both workers parsed on PowerShell {1}. No installer executed." -f $script:fixtures, $PSVersionTable.PSVersion)
