param(
 [Parameter(Mandatory=$true)][string]$ExpectedOrigin,
 [Parameter(Mandatory=$true)][string]$BootstrapSha256
)
# Public entry contains no enrollment capability or Seller credential.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($ExpectedOrigin -cnotmatch '^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?\z' -or $BootstrapSha256 -cnotmatch '^[a-f0-9]{64}\z'){throw 'Trusted origin and SHA256 are required'}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$secret=Read-Host 'Paste your private account enrollment URL' -AsSecureString
$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try{$url=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}
try {
 $pattern='^'+[regex]::Escape($ExpectedOrigin)+'/api/seller-center/landing/bootstrap/[A-Za-z0-9_-]{43}(?:/(?:windows.ps1|macos.sh))?\z'
 if($url -cnotmatch $pattern){throw 'Private enrollment URL does not match trusted origin'}
 $url=$url -replace '/(?:windows.ps1|macos.sh)$',''
 $request=[Net.HttpWebRequest]::Create($url+'/windows.ps1');$request.AllowAutoRedirect=$false;$request.Timeout=60000
 $response=$request.GetResponse()
 try {if([int]$response.StatusCode -ne 200){throw 'Enrollment unavailable'};$memory=New-Object IO.MemoryStream;try{$response.GetResponseStream().CopyTo($memory);$bytes=$memory.ToArray()}finally{$memory.Dispose()}}finally{$response.Dispose()}
 $hasher=[Security.Cryptography.SHA256]::Create()
 try{$hash=([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
 if($hash -cne $BootstrapSha256){throw 'Bootstrap integrity mismatch'}
 $script=[Text.Encoding]::UTF8.GetString($bytes)
 & ([scriptblock]::Create($script))
} catch {Write-Error 'Installation failed. Check the private enrollment URL and trusted bootstrap digest with your administrator.';exit 1}
finally {$url=$null;$secret=$null;$script=$null;$bytes=$null}
