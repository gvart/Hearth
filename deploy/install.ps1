# SPDX-License-Identifier: AGPL-3.0-only
#
# Hearth agent installer for Windows: downloads hearth.exe, verifies its
# SHA-256 (and, when cosign is installed, the release's Sigstore signature),
# installs it to %ProgramFiles%\Hearth, enrolls this device with a hub and
# runs the agent as the Windows service hearth-agent. It mirrors
# deploy/install.sh. Run it in an elevated (Administrator) PowerShell:
#
#   $env:HEARTH_TOKEN = '<token>'
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/gvart/Hearth/<tag>/deploy/install.ps1))) -Version <tag>
#
# The token names the hub (its agent URL and CA fingerprint), so no flag
# does; -Hub gives the hub URL for a token that names none, or one to use
# when this device cannot reach the hub the token names. The token is read
# from HEARTH_TOKEN, which the installer clears at once, and handed to
# `hearth agent join` on stdin, never in a command line.
#
# Re-running upgrades the binary and keeps the device identity (no token
# needed). -Uninstall removes the service and binary; -Purge also deletes the
# agent's data dir.
#
# Windows PowerShell 5.1 and PowerShell 7 both run it. Errors throw, never
# exit, so the shell that ran the one-liner stays open.
#
# Test-only environment overrides (not a supported interface):
#   HEARTH_RELEASE_BASE_URL  base of <tag>/<asset> download URLs
#                            (default https://github.com/gvart/hearth/releases/download)
#   HEARTH_LATEST_URL        JSON with "tag_name" naming the latest release
#   HEARTH_RELEASES_URL      JSON whose first "tag_name" names the newest release,
#                            pre-releases included, used when HEARTH_LATEST_URL fails
[CmdletBinding(PositionalBinding = $false)]
param(
	[string]$Hub = '',
	[string]$Version = '',
	[switch]$LocalCeiling,
	[switch]$Uninstall,
	[switch]$Purge,
	[switch]$Help,
	# Anything else lands here, so that PowerShell never echoes it in a
	# binding error: it may be a mistyped token.
	[Parameter(ValueFromRemainingArguments = $true)]
	[object[]]$Rest
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 downloads slowly while it draws a progress bar.
$ProgressPreference = 'SilentlyContinue'

function Say([string]$Message) { Write-Host "hearth: $Message" }
function Warn([string]$Message) { Write-Warning "hearth: $Message" }
function Die([string]$Message) { throw "hearth: error: $Message" }

# Take the token, then drop HEARTH_TOKEN so no child process inherits it.
$Token = [Environment]::GetEnvironmentVariable('HEARTH_TOKEN', 'Process')
[Environment]::SetEnvironmentVariable('HEARTH_TOKEN', $null, 'Process')
if ($null -eq $Token) { $Token = '' }
$Token = $Token.Trim()

$Repo = 'gvart/hearth'
$ServiceName = 'hearth-agent'
$CosignIdentityRegexp = '^https://github\.com/gvart/Hearth/\.github/workflows/release\.yml@refs/tags/v'
$CosignOidcIssuer = 'https://token.actions.githubusercontent.com'
$CosignInstallUrl = 'https://docs.sigstore.dev/cosign/system_config/installation/'

function EnvOr([string]$Name, [string]$Default) {
	$v = [Environment]::GetEnvironmentVariable($Name, 'Process')
	if ([string]::IsNullOrEmpty($v)) { return $Default }
	return $v
}

$ReleaseBaseUrl = (EnvOr 'HEARTH_RELEASE_BASE_URL' "https://github.com/$Repo/releases/download").TrimEnd('/')
$LatestUrl = EnvOr 'HEARTH_LATEST_URL' "https://api.github.com/repos/$Repo/releases/latest"
# GitHub lists releases newest first; /releases/latest skips pre-releases.
$ReleasesUrl = EnvOr 'HEARTH_RELEASES_URL' "https://api.github.com/repos/$Repo/releases?per_page=1"
if ((EnvOr 'HEARTH_LOCAL_CEILING' '') -eq '1') { $LocalCeiling = $true }

# 64-bit Program Files even from a 32-bit PowerShell.
$ProgramFilesDir = EnvOr 'ProgramW6432' $env:ProgramFiles
$InstallDir = Join-Path $ProgramFilesDir 'Hearth'
$BinPath = Join-Path $InstallDir 'hearth.exe'
$DataDir = Join-Path $env:ProgramData 'Hearth\agent'

function Show-Usage {
	Write-Host @'
Install the Hearth agent on Windows and enroll this device with a hub.
Run it in an elevated (Administrator) PowerShell.

Usage:
  $env:HEARTH_TOKEN='<token>'; install.ps1 [-Hub https://<hub>:7443]   install and enroll
  install.ps1 [-Version vX.Y.Z]                                         upgrade an enrolled agent
  install.ps1 -Uninstall [-Purge]                                       remove the agent

Environment:
  HEARTH_TOKEN          enrollment token from the hub (first install only)
  HEARTH_LOCAL_CEILING  1: as -LocalCeiling

Options:
  -Hub URL          hub URL for enrollment (https://<hub>:7443); the token names
                    the hub, so it is needed only if the token names none, or to
                    reach the hub at another address
  -Version vX.Y.Z   release to install (default: the latest release, or the
                    newest pre-release while there is no stable one)
  -LocalCeiling     the hub may not change what it can do on this device: the
                    agent ignores the capabilities set in the web UI; a re-run
                    keeps the service, and so this
  -Uninstall        stop and remove the service and binary; keep the data dir
  -Purge            with -Uninstall: also delete the data dir (device identity)
  -Help             show this help
'@
}

function Test-Admin {
	$id = [Security.Principal.WindowsIdentity]::GetCurrent()
	return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Platform {
	# PROCESSOR_ARCHITEW6432 is the OS's architecture under a 32-bit PowerShell.
	$arch = EnvOr 'PROCESSOR_ARCHITEW6432' $env:PROCESSOR_ARCHITECTURE
	if ($arch -ne 'AMD64') {
		Die "unsupported architecture: $arch (Hearth ships a Windows build for amd64 only)"
	}
}

# Invoke-Hearth runs hearth.exe with Arguments and fails on a non-zero exit:
# a native command's failure does not throw by itself.
function Invoke-Hearth([string]$Exe, [string[]]$Arguments, [string]$Failure) {
	& $Exe @Arguments
	if ($LASTEXITCODE -ne 0) { Die $Failure }
}

function Get-File([string]$Url, [string]$Dest) {
	Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Dest
}

# Resolve-Version returns the release to install: Requested with a v, or
# the latest release.
function Resolve-Version([string]$Requested) {
	if ($Requested -ne '') {
		if ($Requested.StartsWith('v')) { return $Requested }
		return "v$Requested"
	}
	Say 'looking up the latest release'
	# GitHub answers 404 here while every release is a pre-release.
	$tag = ''
	try { $tag = [string](Invoke-RestMethod -UseBasicParsing -Uri $LatestUrl).tag_name } catch { $tag = '' }
	if ($tag -ne '') { return $tag }
	Say 'found no stable release; looking up the newest release, pre-releases included'
	try { $releases = @(Invoke-RestMethod -UseBasicParsing -Uri $ReleasesUrl) } catch {
		Die "could not look up the releases at $ReleasesUrl; pass -Version vX.Y.Z"
	}
	if ($releases.Count -gt 0) { $tag = [string]$releases[0].tag_name }
	if ($tag -eq '') { Die "found no release at $ReleasesUrl; pass -Version vX.Y.Z" }
	return $tag
}

# Test-Signature checks the keyless Sigstore signature of checksums.txt
# against checksums.txt.sigstore.json when cosign is installed, so that the
# SHA-256 check rests on a file the release workflow signed. Without cosign
# it says so and leaves only the SHA-256 check. The release's other
# signature, the Ed25519 checksums.txt.sig that agents check before they
# upgrade themselves, is not checked here: Windows PowerShell 5.1 has no
# Ed25519.
function Test-Signature([string]$Base, [string]$Tmp) {
	if ($null -eq (Get-Command cosign -ErrorAction SilentlyContinue)) {
		Say "cosign is not installed: the release signature was not checked, only SHA-256 (install cosign v3+ to check it: $CosignInstallUrl)"
		return
	}
	$bundle = Join-Path $Tmp 'checksums.txt.sigstore.json'
	try { Get-File "$Base/checksums.txt.sigstore.json" $bundle } catch {
		Die "could not download $Base/checksums.txt.sigstore.json, the signature of checksums.txt; nothing was installed"
	}
	Say 'verifying the signature of checksums.txt with cosign'
	# cosign talks on stderr, which Windows PowerShell 5.1 turns into a
	# terminating error under 'Stop'; its exit code says how it went.
	$prev = $ErrorActionPreference
	$ErrorActionPreference = 'Continue'
	try {
		$out = & cosign verify-blob --bundle $bundle --certificate-identity-regexp $CosignIdentityRegexp `
			--certificate-oidc-issuer $CosignOidcIssuer (Join-Path $Tmp 'checksums.txt') 2>&1 | Out-String
		$code = $LASTEXITCODE
	} finally {
		$ErrorActionPreference = $prev
	}
	if ($code -ne 0) {
		Write-Host $out
		Die 'the signature of checksums.txt does not verify (not signed by the gvart/Hearth release workflow, or cosign is older than v3); nothing was installed'
	}
	Say 'signature OK: checksums.txt was signed by the gvart/Hearth release workflow'
}

# Get-ChecksumOf prints the SHA-256 checksums.txt lists for Asset, or ''.
function Get-ChecksumOf([string]$Checksums, [string]$Asset) {
	foreach ($line in Get-Content -LiteralPath $Checksums) {
		$f = $line.Trim() -split '\s+'
		if ($f.Count -ge 2 -and $f[1].TrimStart('*') -eq $Asset) { return $f[0].ToLowerInvariant() }
	}
	return ''
}

# Get-Release downloads and verifies the release archive, and returns the
# path of hearth.exe unpacked from it.
function Get-Release([string]$Tmp) {
	$ver = Resolve-Version $Version
	$asset = "hearth_$($ver.Substring(1))_windows_amd64.zip"
	$base = "$ReleaseBaseUrl/$ver"
	Say "downloading checksums for $ver"
	$checksums = Join-Path $Tmp 'checksums.txt'
	try { Get-File "$base/checksums.txt" $checksums } catch {
		Die "could not download $base/checksums.txt (does release $ver exist?)"
	}
	Test-Signature $base $Tmp

	Say "downloading $asset"
	$zip = Join-Path $Tmp $asset
	try { Get-File "$base/$asset" $zip } catch { Die "could not download $base/$asset" }
	$want = Get-ChecksumOf $checksums $asset
	if ($want -eq '') { Die "checksums.txt has no entry for $asset" }
	$got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
	if ($got -ne $want) { Die "checksum mismatch for $asset (expected $want, got $got); nothing was installed" }
	Say 'checksum OK'

	$unpacked = Join-Path $Tmp 'unpacked'
	Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
	$exe = Join-Path $unpacked 'hearth.exe'
	if (-not (Test-Path -LiteralPath $exe)) { Die "$asset holds no hearth.exe" }
	$runs = $false
	try {
		& $exe version *> $null
		$runs = $LASTEXITCODE -eq 0
	} catch { $runs = $false }
	if (-not $runs) { Die 'the downloaded binary does not run on this machine (windows/amd64)' }
	return $exe
}

function Get-AgentService { return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue }

function Stop-AgentService {
	$svc = Get-AgentService
	if ($null -ne $svc -and $svc.Status -ne 'Stopped') {
		Say "stopping service $ServiceName"
		Stop-Service -Name $ServiceName -Force
	}
}

function Install-Binary([string]$Exe) {
	New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
	# A running hearth.exe cannot be overwritten: the service is stopped first.
	Copy-Item -LiteralPath $Exe -Destination "$BinPath.new" -Force
	Move-Item -LiteralPath "$BinPath.new" -Destination $BinPath -Force
	$v = (& $BinPath version | Select-Object -First 1)
	Say "installed $v to $BinPath"
}

function Uninstall-Agent {
	if (Test-Path -LiteralPath $BinPath) {
		Invoke-Hearth $BinPath @('agent', 'service', 'uninstall') "could not remove the $ServiceName service"
		Remove-Item -LiteralPath $BinPath -Force
	} elseif ($null -ne (Get-AgentService)) {
		Stop-AgentService
		& sc.exe delete $ServiceName | Out-Null
	}
	if ((Test-Path -LiteralPath $InstallDir) -and -not (Get-ChildItem -LiteralPath $InstallDir -Force)) {
		Remove-Item -LiteralPath $InstallDir -Force
	}
	Say "removed the $ServiceName service and $BinPath"
	if ($Purge) {
		if (Test-Path -LiteralPath $DataDir) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
		$parent = Split-Path -Parent $DataDir
		if ((Test-Path -LiteralPath $parent) -and -not (Get-ChildItem -LiteralPath $parent -Force)) {
			Remove-Item -LiteralPath $parent -Force
		}
		Say "deleted $DataDir; the device stays listed in the hub until you remove it there"
	} else {
		Say "kept $DataDir (device identity); run with -Uninstall -Purge to delete it"
	}
}

function Install-Agent {
	if ($null -ne $Rest -and $Rest.Count -gt 0) {
		# Do not echo the argument: it may be a mistyped token.
		Die 'unknown argument (see -Help)'
	}
	if ($Help) {
		Show-Usage
		return
	}
	if (-not (Test-Admin)) {
		Die 'this installer needs Administrator rights: re-run it in an elevated PowerShell (Run as administrator)'
	}
	Assert-Platform
	if ($Uninstall -or $Purge) {
		Uninstall-Agent
		return
	}

	$join = $false
	if (Test-Path -LiteralPath (Join-Path $DataDir 'agent.crt')) {
		Say "this device is already enrolled ($DataDir\agent.crt); upgrading and keeping its identity"
		if ($Token -ne '') { Say 'ignoring the enrollment token: a token is not needed for an upgrade' }
	} else {
		if ($Token -eq '') {
			Die "an enrollment token is required for a first install: set `$env:HEARTH_TOKEN='<token>' (create one in the hub UI or with 'hearth token create')"
		}
		if ($Hub -ne '') {
			if (-not $Hub.StartsWith('https://')) { Die "-Hub must be an https:// URL (the hub's agent port, usually 7443)" }
		} elseif ($Token -notmatch '^hearth2\.[^.]*\.[^.]*\..') {
			# A hearth2 token names its hub (hearth2.<secret>.<fingerprint>.<url>).
			Die 'the token names no hub: pass -Hub https://<hub>:7443'
		}
		$join = $true
	}

	# Windows PowerShell 5.1 may not offer TLS 1.2 by default.
	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
	$tmp = Join-Path ([IO.Path]::GetTempPath()) ("hearth-install-" + [Guid]::NewGuid().ToString('N'))
	New-Item -ItemType Directory -Path $tmp | Out-Null
	try {
		$exe = Get-Release $tmp
		Stop-AgentService
		Install-Binary $exe
	} finally {
		Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
	}

	# Before the join: it creates the data dir readable only by SYSTEM and
	# Administrators, where the join writes the device's key. A service that
	# exists already keeps its command line, --local-ceiling included.
	$serviceArgs = @('agent', 'service', 'install', '--data-dir', $DataDir)
	if ($LocalCeiling) { $serviceArgs += '--local-ceiling' }
	Invoke-Hearth $BinPath $serviceArgs "could not install the $ServiceName service"

	if ($join) {
		# The token goes in on stdin, never in a command line.
		$joinArgs = @('agent', 'join', '--data-dir', $DataDir)
		if ($Hub -ne '') {
			Say "enrolling with $Hub"
			$joinArgs += $Hub
			$failure = "enrollment failed (is the token valid and unused, and the hub reachable at ${Hub}?)"
		} else {
			Say 'enrolling with the hub the token names'
			$failure = 'enrollment failed (is the token valid and unused, and the hub it names reachable? -Hub https://<hub>:7443 gives another address)'
		}
		$joinArgs += '-'
		$Token | & $BinPath @joinArgs
		if ($LASTEXITCODE -ne 0) { Die $failure }
	}

	Start-Service -Name $ServiceName
	Say "service $ServiceName is running (logs: Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='$ServiceName'} -MaxEvents 20)"
	Say 'done: this device should show up in the hub UI within seconds'
}

try {
	Install-Agent
} finally {
	$Token = ''
}
