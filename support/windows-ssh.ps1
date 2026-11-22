#requires -Version 5.1
<#
Windows 10 1809+ remote support, run in elevated 64-bit PowerShell.
Only public keys belong in parameters/output. Never pass private keys or passwords.
This is intentionally separate from the seller application installer.
#>
[CmdletBinding()]
param(
    [string] $AccountId,
    [string] $RelayHost,
    [ValidateRange(1, 65535)] [int] $RelayPort = 22,
    [string] $RelayUser,
    [ValidateRange(1024, 65535)] [int] $ReversePort,
    [string] $RelayHostKey,
    [string] $AdminPublicKey,
    [ValidateRange(1024, 65535)] [int] $LocalPort = 29422,
    [switch] $IncludePublicIp,
    [switch] $Uninstall
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$bootstrapSource = $MyInvocation.MyCommand.ScriptBlock.ToString()
$ownerTag = 'WAO.SellerSupport.Windows.v1'
$systemSid = 'S-1-5-18'
$adminsSid = 'S-1-5-32-544'
$trustedSids = @($systemSid, $adminsSid)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open a 64-bit PowerShell window with Run as administrator, using the seller local Windows account.'
}
if (-not [Environment]::Is64BitProcess -or [Environment]::OSVersion.Version.Build -lt 17763) {
    throw 'Requires 64-bit Windows 10 build 1809 or newer and 64-bit PowerShell.'
}
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$parentDir = Join-Path $programData 'WAO'
$stateDir = Join-Path $parentDir 'SellerSupport'
$stateFile = Join-Path $stateDir 'state.json'
$windowsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$powershellExe = Join-Path $windowsDir 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sshDir = Join-Path $windowsDir 'System32\OpenSSH'
$sshdExe = Join-Path $sshDir 'sshd.exe'
$sshExe = Join-Path $sshDir 'ssh.exe'
$keygenExe = Join-Path $sshDir 'ssh-keygen.exe'
$taskNames = @('WAO Seller Support SSHD', 'WAO Seller Support Tunnel')
$ownedFiles = @('state.json', 'sshd_config', 'authorized_keys', 'known_hosts', 'empty_ssh_config',
    'host_ed25519', 'host_ed25519.pub', 'tunnel_ed25519', 'tunnel_ed25519.pub',
    'server.ps1', 'tunnel.ps1', 'uninstall.ps1', 'server-last-error.log', 'tunnel-last-error.log')

function Assert-NoReparse([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing reparse point: $Path"
    }
    return $item
}

function Assert-TrustedAcl([string] $Path) {
    $null = Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trustedSids -notcontains $owner) { throw "Untrusted owner; refusing existing path: $Path" }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $trustedSids -notcontains $rule.IdentityReference.Value) {
            throw "Unexpected access entry; refusing existing path: $Path"
        }
    }
}

function Set-PrivateAcl([string] $Path, [bool] $Directory) {
    if ($Directory) { $acl = New-Object Security.AccessControl.DirectorySecurity }
    else { $acl = New-Object Security.AccessControl.FileSecurity }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($adminsSid)))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in $trustedSids) {
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
        if ($Directory) { $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' }
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)),
            [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-PrivateText([string] $Name, [string] $Text) {
    if ($ownedFiles -notcontains $Name) { throw 'Internal error: unowned filename.' }
    $path = Join-Path $stateDir $Name
    if (Test-Path -LiteralPath $path) { Assert-TrustedAcl $path }
    [IO.File]::WriteAllText($path, $Text, (New-Object Text.UTF8Encoding($false)))
    Set-PrivateAcl $path $false
}

function Normalize-PublicKey([string] $Key, [string] $Label) {
    if ($Key -notmatch '^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]*)?$') {
        throw "$Label must be one OpenSSH ssh-ed25519 public key, never a private key."
    }
    $base64 = $Matches[1]
    try { $bytes = [Convert]::FromBase64String($base64) } catch { throw "Invalid $Label encoding." }
    if ($bytes.Length -ne 51 -or $bytes[0] -ne 0 -or $bytes[1] -ne 0 -or
        $bytes[2] -ne 0 -or $bytes[3] -ne 11 -or
        [Text.Encoding]::ASCII.GetString($bytes, 4, 11) -cne 'ssh-ed25519' -or
        $bytes[15] -ne 0 -or $bytes[16] -ne 0 -or $bytes[17] -ne 0 -or $bytes[18] -ne 32) {
        throw "Invalid $Label Ed25519 wire format."
    }
    return 'ssh-ed25519 ' + [Convert]::ToBase64String($bytes)
}

function Get-BytesFingerprint([byte[]] $Bytes) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return 'SHA256:' + [Convert]::ToBase64String($sha256.ComputeHash($Bytes)).TrimEnd('=') }
    finally { $sha256.Dispose() }
}

function Get-PublicKeyFingerprint([string] $Key) {
    return Get-BytesFingerprint ([Convert]::FromBase64String($Key.Split(' ')[1]))
}

function Resolve-LocalSupportUser([object[]] $Accounts, [string] $CurrentSid) {
    # The caller obtains these records with Get-LocalUser -SID, never by a display
    # name or identity prefix. That lookup also covers Microsoft-connected locals.
    $records = @($Accounts)
    if ($records.Count -ne 1 -or $null -eq $records[0]) {
        throw 'The current Windows SID must resolve to exactly one local user.'
    }
    $account = $records[0]
    foreach ($property in @('SID', 'Enabled', 'Name')) {
        if ($null -eq $account.PSObject.Properties[$property]) {
            throw 'The local Windows account record is incomplete.'
        }
    }
    if ([string]$account.SID -cne $CurrentSid -or [string]::IsNullOrEmpty($CurrentSid)) {
        throw 'The resolved local account SID does not match the current Windows SID.'
    }
    if ($account.Enabled -isnot [bool] -or -not $account.Enabled) {
        throw 'The current local Windows account must be enabled.'
    }
    $sourceProperty = $account.PSObject.Properties['PrincipalSource']
    $source = ''
    if ($null -ne $sourceProperty) { $source = [string]$sourceProperty.Value }
    if ($source -notin @('', 'Local', 'MicrosoftAccount')) {
        throw 'Domain and Microsoft Entra accounts are not supported; use a local Windows account.'
    }
    $name = [string]$account.Name
    # This is a literal OpenSSH AllowUsers token, not a pattern. Permit local
    # Unicode names, spaces and apostrophes, but no OpenSSH/config metacharacters.
    if ($name.Length -lt 1 -or $name.Length -gt 20 -or
        $name -cnotmatch "\A[\p{L}\p{M}\p{Nd}_ .'-]+\z" -or $name -match '\A[ .]+\z') {
        throw 'Local username must contain only letters, digits, spaces, underscore, period, hyphen or apostrophe; SSH patterns and configuration characters are not supported.'
    }
    return $name.ToLowerInvariant()
}

function Invoke-SupportUtf8Process([string] $FileName, [string] $Arguments) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $FileName
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $start.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $process = [Diagnostics.Process]::Start($start)
    try {
        # Drain both pipes concurrently, including when configuration validation fails.
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{ ExitCode = $process.ExitCode
            StandardOutput = $outputTask.GetAwaiter().GetResult()
            StandardError = $errorTask.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}

function Assert-OwnedTask($Task, [string] $Name, [string] $Script, [string] $MachineId) {
    if ($null -eq $Task) { return }
    $expectedArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $stateDir $Script) + '"'
    $actions = @($Task.Actions)
    if ($Task.TaskPath -cne '\' -or $Task.TaskName -cne $Name -or
        $Task.Description -cne "$ownerTag/$MachineId" -or $actions.Count -ne 1 -or
        $actions[0].Execute -ine $powershellExe -or $actions[0].Arguments -cne $expectedArgs -or
        $Task.Principal.UserId -notin @('SYSTEM', 'NT AUTHORITY\SYSTEM', $systemSid) -or
        $Task.Principal.LogonType -ne 'ServiceAccount' -or $Task.Principal.RunLevel -ne 'Highest') {
        throw "Existing task is not owned by this installation: $Name"
    }
}

function Read-OwnedState {
    Assert-TrustedAcl $parentDir
    Assert-TrustedAcl $stateDir
    foreach ($item in @(Get-ChildItem -LiteralPath $stateDir -Force)) {
        if ($item.PSIsContainer -or $ownedFiles -notcontains $item.Name) {
            throw "Unexpected item in support state; refusing to overwrite/remove: $($item.FullName)"
        }
        Assert-TrustedAcl $item.FullName
    }
    Assert-TrustedAcl $stateFile
    $result = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $machineGuid = [guid]::Empty
    if ($result.owner -cne $ownerTag -or $result.schema -ne 1 -or
        -not [guid]::TryParse([string]$result.machineId, [ref]$machineGuid)) {
        throw 'State directory is not a recognized WAO support installation.'
    }
    return $result
}

function Remove-OwnedInstallation($State) {
    for ($i = 0; $i -lt $taskNames.Count; $i++) {
        $script = @('server.ps1', 'tunnel.ps1')[$i]
        $task = Get-ScheduledTask -TaskName $taskNames[$i] -TaskPath '\' -ErrorAction SilentlyContinue
        Assert-OwnedTask $task $taskNames[$i] $script $State.machineId
    }
    foreach ($name in $taskNames) {
        $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if ($null -ne $task) {
            $task | Disable-ScheduledTask | Out-Null
            $task | Stop-ScheduledTask
        }
    }
    Start-Sleep -Seconds 2
    # Never remove keys/config while any process still has this installation in its command line.
    $remaining = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ProcessId -ne $PID -and $_.CommandLine -and
        $_.CommandLine.IndexOf($stateDir, [StringComparison]::OrdinalIgnoreCase) -ge 0
    })
    if ($remaining.Count -gt 0) { throw 'Support process still running. Reboot, then rerun uninstall; state has been retained.' }
    foreach ($name in $taskNames) {
        $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if ($null -ne $task) { $task | Unregister-ScheduledTask -Confirm:$false }
    }
    # Recheck every path before deleting. No recursive delete, no parent removal, no capability removal.
    $null = Read-OwnedState
    foreach ($name in $ownedFiles | Where-Object { $_ -ne 'state.json' }) {
        $path = Join-Path $stateDir $name
        if (Test-Path -LiteralPath $path) { Assert-TrustedAcl $path; Remove-Item -LiteralPath $path -Force }
    }
    Remove-Item -LiteralPath $stateFile -Force
    Remove-Item -LiteralPath $stateDir -Force
}

if ($Uninstall) {
    if (-not (Test-Path -LiteralPath $stateDir)) { Write-Output 'Support installation is absent.'; return }
    $state = Read-OwnedState
    Remove-OwnedInstallation $state
    Write-Output 'Support tasks and dedicated state removed. Revoke this machine tunnel key on the relay separately.'
    return
}

if ($AccountId -cnotmatch '^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$') {
    throw 'AccountId is required: 1-64 lowercase ASCII letters/digits/underscore/hyphen (UUID accepted).'
}
if ($RelayUser -cnotmatch '^[a-z_][a-z0-9_-]{0,31}$') { throw 'RelayUser is required: a strict Unix account name.' }
if (-not $PSBoundParameters.ContainsKey('ReversePort')) { throw 'ReversePort is required: the dedicated port assigned to this machine on the relay.' }
$ip = $null
if (-not [Net.IPAddress]::TryParse($RelayHost, [ref]$ip) -or
    $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $RelayHost) {
    throw 'RelayHost must be a canonical, fixed public IPv4 address.'
}
$octets = $ip.GetAddressBytes()
if ($octets[0] -eq 0 -or $octets[0] -eq 10 -or $octets[0] -eq 127 -or $octets[0] -ge 224 -or
    ($octets[0] -eq 100 -and $octets[1] -ge 64 -and $octets[1] -le 127) -or
    ($octets[0] -eq 169 -and $octets[1] -eq 254) -or
    ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
    ($octets[0] -eq 192 -and ($octets[1] -eq 0 -or $octets[1] -eq 168)) -or
    ($octets[0] -eq 198 -and ($octets[1] -eq 18 -or $octets[1] -eq 19 -or ($octets[1] -eq 51 -and $octets[2] -eq 100))) -or
    ($octets[0] -eq 203 -and $octets[1] -eq 0 -and $octets[2] -eq 113)) {
    throw 'RelayHost must be publicly routable, not a local, shared, test, or documentation address.'
}
if ($LocalPort -eq 22) { throw 'Local support port must be separate from global sshd.' }
$RelayHostKey = Normalize-PublicKey $RelayHostKey 'RelayHostKey'
$AdminPublicKey = Normalize-PublicKey $AdminPublicKey 'AdminPublicKey'
if ($RelayHostKey -ceq $AdminPublicKey) { throw 'Relay host and controller keys must be independent.' }
try { $localAccounts = @(Get-LocalUser -SID $identity.User -ErrorAction Stop) }
catch { throw 'The current Windows SID could not be resolved as a local account. Domain and Microsoft Entra accounts are not supported.' }
$localUser = Resolve-LocalSupportUser -Accounts $localAccounts -CurrentSid $identity.User.Value
$binding = [ordered]@{
    accountId = $AccountId; relayHost = $RelayHost; relayPort = $RelayPort; relayUser = $RelayUser
    reversePort = $ReversePort; localPort = $LocalPort; relayHostKey = $RelayHostKey
    adminPublicKey = $AdminPublicKey; userSid = $identity.User.Value; localUser = $localUser
}
$machineGuidText = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid')
$machineGuid = [guid]::Empty
if (-not [guid]::TryParse($machineGuidText, [ref]$machineGuid) -or $machineGuid -eq [guid]::Empty) {
    throw 'Cannot resolve a stable Windows installation identity; refusing to bind this machine.'
}
$deviceFingerprint = Get-BytesFingerprint ([Text.Encoding]::UTF8.GetBytes($ownerTag + ':' + $machineGuid.ToString('D')))

# Walk ancestors without following a junction, including ProgramData itself.
$ancestor = Get-Item -LiteralPath $programData -Force
while ($null -ne $ancestor) { $null = Assert-NoReparse $ancestor.FullName; $ancestor = $ancestor.Parent }
if (Test-Path -LiteralPath $stateDir) {
    $state = Read-OwnedState
    if ($state.deviceFingerprint -cne $deviceFingerprint) { throw 'Support state belongs to a different Windows installation.' }
    foreach ($name in $binding.Keys) {
        if ([string]$state.binding.$name -cne [string]$binding[$name]) {
            throw "Existing installation has a different binding ($name). Uninstall and revoke the previous key before rebinding."
        }
    }
} else {
    if (Test-Path -LiteralPath $parentDir) { Assert-TrustedAcl $parentDir }
    else {
        $null = New-Item -ItemType Directory -Path $parentDir
        Set-PrivateAcl $parentDir $true
    }
    foreach ($name in $taskNames) {
        if (Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue) {
            throw "Task already exists without owned state: $name"
        }
    }
    $null = New-Item -ItemType Directory -Path $stateDir
    Set-PrivateAcl $stateDir $true
    $state = [pscustomobject]@{ owner = $ownerTag; schema = 1; machineId = [guid]::NewGuid().ToString()
        deviceFingerprint = $deviceFingerprint; binding = $binding }
    Write-PrivateText 'state.json' ($state | ConvertTo-Json -Depth 5)
}
try {
for ($i = 0; $i -lt $taskNames.Count; $i++) {
    $task = Get-ScheduledTask -TaskName $taskNames[$i] -TaskPath '\' -ErrorAction SilentlyContinue
    Assert-OwnedTask $task $taskNames[$i] @('server.ps1', 'tunnel.ps1')[$i] $state.machineId
}
$listenersBefore = @(Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue)
foreach ($listener in $listenersBefore) {
    $existingProcess = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $listener.OwningProcess)
    $expectedConfig = Join-Path $stateDir 'sshd_config'
    if ($listener.LocalAddress -cne '127.0.0.1' -or $existingProcess.ExecutablePath -ine $sshdExe -or
        -not $existingProcess.CommandLine -or
        $existingProcess.CommandLine.IndexOf($expectedConfig, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw 'Local support port is already occupied by another process. No support task has been started.'
    }
}

# Windows capability installation may create a default port-22 rule. Restore its absence
# if and only if this invocation introduced it; never alter a preexisting firewall rule.
$firewallBefore = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
$serviceBefore = Get-CimInstance Win32_Service -Filter "Name = 'sshd'"
$globalConfig = Join-Path $programData 'ssh\sshd_config'
$globalConfigHash = $null
if (Test-Path -LiteralPath $globalConfig -PathType Leaf) {
    $globalConfigHash = (Get-FileHash -LiteralPath $globalConfig -Algorithm SHA256).Hash
}
try {
    foreach ($feature in @('OpenSSH.Client~~~~0.0.1.0', 'OpenSSH.Server~~~~0.0.1.0')) {
        $capability = Get-WindowsCapability -Online -Name $feature
        if ($capability.State -ne 'Installed') {
            $installation = Add-WindowsCapability -Online -Name $feature
            if ($installation.RestartNeeded) { throw 'OpenSSH capability installation requires a restart. Restart Windows and rerun the same command.' }
        }
    }
} finally {
    if ($firewallBefore.Count -eq 0) {
        Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
}
$serviceAfter = Get-CimInstance Win32_Service -Filter "Name = 'sshd'"
if ($null -ne $serviceBefore -and ($null -eq $serviceAfter -or
    $serviceBefore.State -ne $serviceAfter.State -or $serviceBefore.StartMode -ne $serviceAfter.StartMode -or
    $serviceBefore.PathName -cne $serviceAfter.PathName)) {
    throw 'Windows capability installation unexpectedly changed the existing global sshd service. Inspect Windows servicing; support has not started.'
}
if ($globalConfigHash -and ((Get-FileHash -LiteralPath $globalConfig -Algorithm SHA256).Hash -cne $globalConfigHash)) {
    throw 'Windows servicing unexpectedly changed global sshd_config. Support has not started.'
}
foreach ($before in $firewallBefore) {
    $after = Get-NetFirewallRule -Name $before.Name
    if ($after.Enabled -ne $before.Enabled -or $after.Direction -ne $before.Direction -or
        $after.Action -ne $before.Action -or $after.Profile -ne $before.Profile) {
        throw 'Windows servicing unexpectedly changed a preexisting global SSH firewall rule. Support has not started.'
    }
}
foreach ($executable in @($sshdExe, $sshExe, $keygenExe)) {
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Windows OpenSSH installation is incomplete; no fallback binary is downloaded.' }
}

function Ensure-Key([string] $Name) {
    $privatePath = Join-Path $stateDir $Name
    $publicPath = $privatePath + '.pub'
    if (-not (Test-Path -LiteralPath $privatePath)) {
        if (Test-Path -LiteralPath $publicPath) { throw "Orphan public key: $Name" }
        # ProcessStartInfo passes literal -N "" to Windows CreateProcess, including on PowerShell 5.1.
        # No cmd.exe, Invoke-Expression, interpolation of user values, or private-key output.
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $keygenExe
        $start.Arguments = '-q -t ed25519 -f "' + $privatePath + '" -N "" -C wao-seller-support'
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($start)
        $null = $process.StandardOutput.ReadToEnd()
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "Ed25519 key generation failed: $errorText" }
        $process.Dispose()
        Set-PrivateAcl $privatePath $false
        Set-PrivateAcl $publicPath $false
    }
    Assert-TrustedAcl $privatePath
    $derived = & $keygenExe -y -f $privatePath 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Cannot read owned key: $Name" }
    $key = Normalize-PublicKey ($derived -join '') $Name
    if (Test-Path -LiteralPath $publicPath) {
        Assert-TrustedAcl $publicPath
        if ((Normalize-PublicKey ((Get-Content -LiteralPath $publicPath -Raw).Trim()) $Name) -cne $key) {
            throw "Private/public key mismatch: $Name"
        }
    } else { Write-PrivateText ($Name + '.pub') ($key + "`n") }
    return $key
}
$hostPublicKey = Ensure-Key 'host_ed25519'
$tunnelPublicKey = Ensure-Key 'tunnel_ed25519'
if (@($hostPublicKey, $tunnelPublicKey, $RelayHostKey, $AdminPublicKey | Select-Object -Unique).Count -ne 4) {
    throw 'Host, tunnel, relay and controller keys must all be independent.'
}
Write-PrivateText 'authorized_keys' ($AdminPublicKey + "`n")
$knownHostName = $RelayHost
if ($RelayPort -ne 22) { $knownHostName = '[' + $RelayHost + ']:' + $RelayPort }
Write-PrivateText 'known_hosts' ($knownHostName + ' ' + $RelayHostKey + "`n")
Write-PrivateText 'empty_ssh_config' "# Isolated support client: intentionally empty.`n"
$configPath = Join-Path $stateDir 'sshd_config'
$configDir = $stateDir.Replace('\', '/')
$sshdConfig = @"
Port $LocalPort
AddressFamily inet
ListenAddress 127.0.0.1
HostKey "$configDir/host_ed25519"
AuthorizedKeysFile "$configDir/authorized_keys"
AllowUsers "$localUser"
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
PermitEmptyPasswords no
AllowTcpForwarding no
AllowAgentForwarding no
GatewayPorts no
MaxAuthTries 3
LoginGraceTime 30
LogLevel ERROR
Subsystem sftp internal-sftp
"@
Write-PrivateText 'sshd_config' ($sshdConfig + "`n")
& $sshdExe -t -f $configPath
if ($LASTEXITCODE -ne 0) { throw 'Isolated sshd configuration validation failed; tasks were not registered.' }
# OpenSSH emits UTF-8. Windows PowerShell 5.1 native stdout otherwise follows
# the console code page, which can corrupt an otherwise valid Unicode username.
$dump = Invoke-SupportUtf8Process $sshdExe ('-T -f "' + $configPath + '"')
if ($dump.ExitCode -ne 0) { throw 'Cannot inspect effective sshd configuration.' }
$effective = @($dump.StandardOutput -split '\r?\n' | Where-Object { $_.Length -gt 0 })
foreach ($required in @('passwordauthentication no', 'pubkeyauthentication yes', 'authenticationmethods publickey',
    'allowtcpforwarding no', 'allowagentforwarding no', "allowusers $localUser", "listenaddress 127.0.0.1:$LocalPort")) {
    if ($effective -notcontains $required) { throw "Unexpected effective sshd setting: $required" }
}
if (@($effective | Where-Object { $_ -like 'listenaddress *' }).Count -ne 1) { throw 'sshd must listen only on loopback.' }

# Workers are static text; all public parameters are loaded as JSON and passed as native arguments.
$serverScript = @'
#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$windowsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$sshd = Join-Path $windowsDir 'System32\OpenSSH\sshd.exe'
$config = Join-Path $PSScriptRoot 'sshd_config'
$log = Join-Path $PSScriptRoot 'server-last-error.log'
# Windows PowerShell 5.1 must not turn a native stderr diagnostic into a terminating exception.
$ErrorActionPreference = 'Continue'
& $sshd -D -e -f $config 2> $log
exit $LASTEXITCODE
'@
$tunnelScript = @'
#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$state = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'state.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$b = $state.binding
$windowsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$ssh = Join-Path $windowsDir 'System32\OpenSSH\ssh.exe'
$private = Join-Path $PSScriptRoot 'tunnel_ed25519'
$known = (Join-Path $PSScriptRoot 'known_hosts').Replace('\', '/')
$config = Join-Path $PSScriptRoot 'empty_ssh_config'
$log = Join-Path $PSScriptRoot 'tunnel-last-error.log'
$forward = '127.0.0.1:' + $b.reversePort + ':127.0.0.1:' + $b.localPort
$sshArguments = @('-F', $config, '-4', '-N', '-T', '-p', [string]$b.relayPort,
    '-l', [string]$b.relayUser, '-i', $private,
    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
    '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no', '-o', 'StrictHostKeyChecking=yes',
    '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', ('UserKnownHostsFile="' + $known + '"'),
    '-o', 'GlobalKnownHostsFile=NUL', '-o', 'UpdateHostKeys=no', '-o', 'VerifyHostKeyDNS=no',
    '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=15', '-o', 'ConnectionAttempts=1',
    '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
    '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'LogLevel=ERROR',
    '-R', $forward, [string]$b.relayHost)
while ($true) {
    # A failed authentication is expected until the operator registers the public tunnel key.
    # Overwrite on retry to bound normal failure logging. No fallback authentication/relay.
    $ErrorActionPreference = 'Continue'
    try { & $ssh @sshArguments 2> $log }
    finally { $ErrorActionPreference = 'Stop' }
    Start-Sleep -Seconds 15
}
'@
Write-PrivateText 'server.ps1' ($serverScript + "`n")
Write-PrivateText 'tunnel.ps1' ($tunnelScript + "`n")
# Retain the invoked script block for offline removal, including verified in-memory bootstraps.
# This contains source code only; runtime parameters and generated private keys are not included.
Write-PrivateText 'uninstall.ps1' $bootstrapSource

for ($i = 0; $i -lt $taskNames.Count; $i++) {
    $scriptPath = Join-Path $stateDir @('server.ps1', 'tunnel.ps1')[$i]
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $scriptPath + '"'
    $action = New-ScheduledTaskAction -Execute $powershellExe -Argument $arguments -WorkingDirectory $stateDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $systemSid -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([timespan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -MultipleInstances IgnoreNew
    $definition = New-ScheduledTask -Action $action -Trigger $trigger -Principal $taskPrincipal `
        -Settings $settings -Description "$ownerTag/$($state.machineId)"
    $existing = Get-ScheduledTask -TaskName $taskNames[$i] -TaskPath '\' -ErrorAction SilentlyContinue
    Assert-OwnedTask $existing $taskNames[$i] @('server.ps1', 'tunnel.ps1')[$i] $state.machineId
    if ($null -eq $existing) {
        Register-ScheduledTask -TaskName $taskNames[$i] -TaskPath '\' -InputObject $definition | Out-Null
    } else {
        # Same binding may be resumed after a partial setup; update only our exact tasks.
        $existing | Stop-ScheduledTask
        Set-ScheduledTask -TaskName $taskNames[$i] -TaskPath '\' -InputObject $definition | Out-Null
    }
    Start-ScheduledTask -TaskName $taskNames[$i] -TaskPath '\'
}

$listening = $false
for ($attempt = 0; $attempt -lt 15; $attempt++) {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) {
        if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -cne '127.0.0.1') {
            throw 'Support port has an unexpected listener. Inspect locally; report has not been issued.'
        }
        $process = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $listeners[0].OwningProcess)
        if ($process.ExecutablePath -ine $sshdExe -or -not $process.CommandLine -or
            $process.CommandLine.IndexOf($configPath, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw 'Local port belongs to another process; support is not ready.'
        }
        $listening = $true
        break
    }
    Start-Sleep -Seconds 1
}
if (-not $listening) { throw "SYSTEM sshd did not listen. Inspect $stateDir\server-last-error.log and Task Scheduler; no remote readiness is claimed." }
foreach ($name in $taskNames) {
    $task = Get-ScheduledTask -TaskName $name -TaskPath '\'
    if ($task.State -ne 'Running') { throw "Support task is not running: $name" }
}
$hostFingerprint = Get-PublicKeyFingerprint $hostPublicKey
$publicIp = [ordered]@{ status = 'notRequested'; address = $null; error = $null }
if ($IncludePublicIp) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $response = Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 10 -MaximumRedirection 0
        $observedIp = $null
        if (-not [Net.IPAddress]::TryParse([string]$response.ip, [ref]$observedIp)) { throw 'Invalid IP response.' }
        $publicIp.status = 'observed'; $publicIp.address = $observedIp.ToString()
    } catch { $publicIp.status = 'unavailable'; $publicIp.error = 'Public IP lookup failed; no replacement source used.' }
}
[ordered]@{
    accountId = $AccountId; machineId = $state.machineId; hostname = [Environment]::MachineName
    deviceFingerprint = $deviceFingerprint; bootstrapVersion = 'windows-support-v1'
    adminPublicKeyFingerprint = (Get-PublicKeyFingerprint $AdminPublicKey)
    localUsername = $localUser; timezone = [TimeZoneInfo]::Local.Id; publicIp = $publicIp
    hostPublicKey = $hostPublicKey; hostFingerprint = $hostFingerprint; tunnelPublicKey = $tunnelPublicKey
    relay = [ordered]@{ host = $RelayHost; port = $RelayPort; user = $RelayUser; reversePort = $ReversePort }
    readiness = [ordered]@{ status = 'pendingRelayAuthorization'; localLoopbackListening = $true
        tasksRunning = $true; endToEndVerified = $false }
} | ConvertTo-Json -Depth 6
} catch {
    # A local validation failure must not leave a tunnel forwarding an unexpected service.
    foreach ($name in $taskNames) {
        try {
            $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
            if ($null -ne $task) {
                $scriptName = if ($name -ceq $taskNames[0]) { 'server.ps1' } else { 'tunnel.ps1' }
                Assert-OwnedTask $task $name $scriptName $state.machineId
                $task | Disable-ScheduledTask | Out-Null
                $task | Stop-ScheduledTask
            }
        } catch { Write-Warning ('Could not stop owned support task: ' + $name) }
    }
    throw
}
