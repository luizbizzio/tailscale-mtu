[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$Force,
    [string]$ResultPath,
    [switch]$UI,
    [switch]$RunLoop,
    [switch]$Apply,
    [switch]$Status,
    [switch]$Update,
    [switch]$CheckUpdate,
    [switch]$Repair,
    [Alias('Version')]
    [switch]$ShowVersion,
    [Alias('h','?')]
    [switch]$Help,
    [string]$IPv4,
    [string]$IPv6,
    [int]$Interval,
    [Alias('EnableEnforcement')]
    [switch]$Enable,
    [Alias('DisableEnforcement')]
    [switch]$Disable,
    [switch]$NoOpenUi
)

$AppVersion = '1.0.0'
$AppDisplayName = 'Tailscale MTU'
$ServiceName = 'TailscaleMTU'
$ServiceDisplayName = 'Tailscale MTU'
$ServiceDescription = 'Keeps Tailscale MTU persistent based on user config.'
$AppDir = Join-Path $env:ProgramData 'TailscaleMTU'
$LogDir = Join-Path $AppDir 'logs'
$ScriptDest = Join-Path $AppDir 'tailscale-mtu.ps1'
$ConfigPath = Join-Path $AppDir 'config.json'
$StatePath = Join-Path $AppDir 'state.json'
$StateMutexName = 'Global\TailscaleMTU_StateLock'
$UiMutexName = 'Local\TailscaleMTU_UiLock'
$UninstallDialogMutexName = 'Local\TailscaleMTU_UninstallDialogLock'
$ApplyRequestedEventName = 'Global\TailscaleMTU_ApplyRequested'
$NssmPath = Join-Path $AppDir 'nssm.exe'
$UiLauncherVbsPath = Join-Path $AppDir 'TailscaleMTULauncher.vbs'
$ReleaseBaseUrl = 'https://github.com/luizbizzio/tailscale-mtu/releases/latest/download'
$GitHubLatestReleaseApiUrl = 'https://api.github.com/repos/luizbizzio/tailscale-mtu/releases/latest'
$NssmDownloadUrl = "$ReleaseBaseUrl/nssm.exe"
$IconPath = Join-Path $AppDir 'tailscale-mtu.ico'
$IconDownloadUrl = "$ReleaseBaseUrl/tailscale-mtu.ico"
$MinMtuIPv4 = 576
$MinMtuIPv6 = 1280
$MaxMtu = 9000
$DefaultCheckIntervalSeconds = 60
$LoopTickMilliseconds = 1000
$MaxIdleSleepMilliseconds = 5000
$HeartbeatWriteSeconds = 60
$AppUserModelId = 'LuizBizzio.TailscaleMTU'
$ScriptPath = $PSCommandPath
if (-not $ScriptPath) { $ScriptPath = $MyInvocation.MyCommand.Path }

if ($ShowVersion) {
    Write-Output $AppVersion
    exit 0
}

if ($Help) {
    @'
Tailscale MTU

Usage:
  .\tailscale-mtu.ps1 [command] [options]

Commands:
  -Install                         Install or repair app, service, shortcut, and assets.
  -Uninstall                       Confirm and uninstall. Keeps config/state/logs unless -Purge is used.
  -Uninstall -Force                Uninstall without confirmation. Keeps config/state/logs.
  -Uninstall -Purge                Confirm and remove service, app files, config, state, and logs.
  -Uninstall -Purge -Force         Remove service, app files, config, state, and logs without confirmation.
  -ResultPath <path>                Optional automation result JSON path for uninstall callers.
  -Repair                          Repair local service, shortcut, launcher, and assets without changing version.
  -Update                          Check latest GitHub Release and update if a newer version exists.
  -CheckUpdate                     Check latest GitHub Release without installing anything.
  -Status                          Print machine-readable JSON status for automation.
  -Version                         Print script version.
  -UI                              Open the graphical interface.
  -Apply                           Apply current config immediately once.
  -RunLoop                         Run the background enforcement loop.

Configuration commands:
  -IPv4 <mtu>                      Set desired IPv4 MTU.
  -IPv6 <mtu>                      Set desired IPv6 MTU.
  -Interval <seconds>              Set enforcement check interval in seconds.
  -Enable                          Enable MTU enforcement.
  -Disable                         Disable MTU enforcement.

Examples:
  .\tailscale-mtu.ps1 -IPv4 1280 -IPv6 1280 -Interval 60 -Enable
  .\tailscale-mtu.ps1 -Disable
  .\tailscale-mtu.ps1 -Status
  .\tailscale-mtu.ps1 -CheckUpdate
  .\tailscale-mtu.ps1 -Uninstall
  .\tailscale-mtu.ps1 -Uninstall -Purge -Force

Exit codes:
  0 = success
  1 = general error
  2 = invalid parameter or invalid config value
  3 = no update available
  4 = administrator elevation required or elevation could not be started
'@ | Write-Output
    exit 0
}

$ScriptSourceText = $null
try {
    if (-not $ScriptPath -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.ScriptBlock) {
        $ScriptSourceText = $MyInvocation.MyCommand.ScriptBlock.ToString()
    }
} catch {
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-ResolvedScriptPath {
    if ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath)) {
        return $ScriptPath
    }

    if (-not [string]::IsNullOrWhiteSpace($ScriptSourceText)) {
        $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) ("Tailscale-MTU-" + [guid]::NewGuid().ToString('N') + ".ps1")
        Set-Content -LiteralPath $tempScript -Value $ScriptSourceText -Encoding UTF8 -Force
        return $tempScript
    }

    throw 'Could not resolve current script path. Save the script to a .ps1 file and run it again.'
}

function Invoke-AdminRelaunchIfNeeded {
    param([string[]]$ModeSwitches)

    if (Test-IsAdmin) { return }

    $resolvedScriptPath = Get-ResolvedScriptPath

    $processArgs = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-WindowStyle', 'Hidden'
        '-File', "`"$resolvedScriptPath`""
    )

    if ($ModeSwitches) {
        $processArgs += $ModeSwitches
    }

    Start-Process -FilePath 'powershell.exe' -ArgumentList ($processArgs -join ' ') -Verb RunAs -WindowStyle Hidden | Out-Null
    exit
}

function Initialize-AppDirectory {
    if (-not (Test-Path -LiteralPath $AppDir)) {
        New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
}

function Set-AppPermissions {
    Initialize-AppDirectory

    $usersSid = '*S-1-5-32-545'

    try {
        & icacls "$AppDir" '/grant:r' "${usersSid}:(RX)" | Out-Null
    } catch {
    }

    try {
        if (Test-Path -LiteralPath $LogDir) {
            & icacls "$LogDir" '/grant:r' "${usersSid}:(OI)(CI)(M)" | Out-Null
        }
    } catch {
    }

    foreach ($p in @($ConfigPath, $StatePath)) {
        try {
            if (Test-Path -LiteralPath $p) {
                & icacls "$p" '/grant:r' "${usersSid}:(M)" | Out-Null
            }
        } catch {
        }
    }

    foreach ($p in @($ScriptDest, $NssmPath, $UiLauncherVbsPath, $IconPath)) {
        try {
            if (Test-Path -LiteralPath $p) {
                & icacls "$p" '/grant:r' "${usersSid}:(RX)" | Out-Null
            }
        } catch {
        }
    }
}

function Get-NowIsoUtc {
    [DateTime]::UtcNow.ToString('o')
}

function Write-UninstallResult {
    param(
        [string]$Status,
        [string]$Message,
        [int]$ExitCode = 0
    )

    if ([string]::IsNullOrWhiteSpace([string]$ResultPath)) { return }

    try {
        $parent = Split-Path -Parent $ResultPath
        if (-not [string]::IsNullOrWhiteSpace([string]$parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }

        $payload = [pscustomobject]@{
            status = [string]$Status
            message = [string]$Message
            purge = [bool]$Purge.IsPresent
            exit_code = [int]$ExitCode
            timestamp_utc = Get-NowIsoUtc
        }

        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8 -Force
    } catch {
    }
}

function ConvertTo-UtcDateTimeSafe {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        return [DateTime]::Parse($Value).ToUniversalTime()
    } catch {
        return $null
    }
}



function Set-ProcessAppUserModelId {
    try {
        if (-not ('TailscaleMtu.Shell32' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace TailscaleMtu {
    public static class Shell32 {
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
        public static extern int SetCurrentProcessExplicitAppUserModelID(string appID);
    }
}
"@ -ErrorAction Stop | Out-Null
        }

        [void][TailscaleMtu.Shell32]::SetCurrentProcessExplicitAppUserModelID($AppUserModelId)
    } catch {
    }
}

function Install-AppIcon {
    Initialize-AppDirectory

    $needDownload = $true
    if (Test-Path -LiteralPath $IconPath) {
        try {
            $fi = Get-Item -LiteralPath $IconPath -ErrorAction Stop
            if ($fi.Length -gt 0) { $needDownload = $false }
        } catch {
        }
    }

    if (-not $needDownload) { return $IconPath }

    $tmp = "$IconPath.download"
    if (Test-Path -LiteralPath $tmp) {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }

    Invoke-WebRequest -Uri $IconDownloadUrl -OutFile $tmp -UseBasicParsing -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $tmp)) {
        throw 'Failed to download app icon.'
    }

    $fiTmp = Get-Item -LiteralPath $tmp -ErrorAction Stop
    if ($fiTmp.Length -le 0) {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw 'Downloaded icon file is empty.'
    }

    Move-Item -LiteralPath $tmp -Destination $IconPath -Force
    return $IconPath
}

function Backup-BrokenJsonFile {
    param(
        [string]$Path,
        [string]$Reason
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $backupPath = "$Path.broken.$timestamp"
        $i = 0
        while (Test-Path -LiteralPath $backupPath) {
            $i++
            $backupPath = "$Path.broken.$timestamp.$i"
        }

        Move-Item -LiteralPath $Path -Destination $backupPath -Force
        return $backupPath
    } catch {
        return $null
    }
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $lastError = $null
    for ($i = 0; $i -lt 5; $i++) {
        try {
            $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
            return $raw | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Milliseconds 40
        }
    }

    Backup-BrokenJsonFile -Path $Path -Reason $lastError | Out-Null
    return $null
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Data
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'JSON path is empty.'
    }

    $json = ($Data | ConvertTo-Json -Depth 20) + [Environment]::NewLine
    $dir = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = (Get-Location).Path }
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullDir = [System.IO.Path]::GetDirectoryName($fullPath)
    if ([string]::IsNullOrWhiteSpace($fullDir)) { $fullDir = $dir }

    $name = [System.IO.Path]::GetFileName($fullPath)
    if ([string]::IsNullOrWhiteSpace($name)) { $name = 'json' }

    $tmp = Join-Path $fullDir (".$name." + [guid]::NewGuid().ToString('N') + '.tmp')
    $backup = Join-Path $fullDir (".$name." + [guid]::NewGuid().ToString('N') + '.replace.bak')
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $fs = $null

    try {
        $bytes = $encoding.GetBytes($json)
        $fs = [System.IO.File]::Open($tmp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Flush($true)
        $fs.Dispose()
        $fs = $null

        if (Test-Path -LiteralPath $fullPath) {
            try {
                [System.IO.File]::Replace($tmp, $fullPath, $backup, $true)
            } catch {
                Copy-Item -LiteralPath $tmp -Destination $fullPath -Force
            }
        } else {
            [System.IO.File]::Move($tmp, $fullPath)
        }
    } finally {
        if ($fs) {
            try { $fs.Dispose() } catch {}
        }
        foreach ($cleanupPath in @($tmp, $backup)) {
            try {
                if ($cleanupPath -and (Test-Path -LiteralPath $cleanupPath)) {
                    Remove-Item -LiteralPath $cleanupPath -Force -ErrorAction SilentlyContinue
                }
            } catch {
            }
        }
    }
}
function Invoke-WithStateLock {
    param(
        [scriptblock]$ScriptBlock,
        [int]$TimeoutMilliseconds = 5000
    )

    $mutex = $null
    $hasLock = $false

    try {
        try {
            $mutex = [System.Threading.Mutex]::new($false, $StateMutexName)
        } catch [System.UnauthorizedAccessException] {
            return & $ScriptBlock
        } catch {
            return & $ScriptBlock
        }

        try {
            $hasLock = $mutex.WaitOne($TimeoutMilliseconds)
        } catch [System.Threading.AbandonedMutexException] {
            $hasLock = $true
        } catch [System.UnauthorizedAccessException] {
            return & $ScriptBlock
        }

        if (-not $hasLock) {
            throw "Timeout waiting for state lock after $TimeoutMilliseconds ms."
        }

        return & $ScriptBlock
    } finally {
        if ($hasLock -and $mutex) {
            try { [void]$mutex.ReleaseMutex() } catch {}
        }

        if ($mutex) {
            $mutex.Dispose()
        }
    }
}
function Get-ClampedInt {
    param(
        [int]$Value,
        [int]$Min,
        [int]$Max
    )
    if ($Value -lt $Min) { return $Min }
    if ($Value -gt $Max) { return $Max }
    return $Value
}

function Get-DefaultConfig {
    [ordered]@{
        enabled = $true
        desired_mtu_ipv4 = 1280
        desired_mtu_ipv6 = 1280
        interface_match = 'Tailscale'
        check_interval_seconds = $DefaultCheckIntervalSeconds
    }
}

function Get-DefaultState {
    [ordered]@{
        pending_apply = $false
        apply_requested_utc = $null
        last_result = 'never'
        last_error = $null
        last_check_utc = $null
        last_apply_utc = $null
        service_heartbeat_utc = $null
        desired_mtu_ipv4 = 1280
        desired_mtu_ipv6 = 1280
        detected_interface = $null
        current_mtu_ipv4 = $null
        current_mtu_ipv6 = $null
    }
}

function Initialize-ConfigStore {
    Initialize-AppDirectory
    $cfg = Read-JsonFile -Path $ConfigPath
    $defaults = Get-DefaultConfig

    if (-not $cfg) {
        Write-JsonFile -Path $ConfigPath -Data $defaults
        return [pscustomobject]$defaults
    }

    $changed = $false

    $oldMtu = $null
    try {
        if ($cfg.PSObject.Properties['desired_mtu']) {
            $oldMtu = [int]$cfg.desired_mtu
        }
    } catch {
        $oldMtu = $null
    }

    if (-not $cfg.PSObject.Properties['desired_mtu_ipv4']) {
        $v4 = if ($null -ne $oldMtu) { [int](Get-ClampedInt -Value $oldMtu -Min $MinMtuIPv4 -Max $MaxMtu) } else { [int]$defaults.desired_mtu_ipv4 }
        Add-Member -InputObject $cfg -MemberType NoteProperty -Name 'desired_mtu_ipv4' -Value $v4
        $changed = $true
    }

    if (-not $cfg.PSObject.Properties['desired_mtu_ipv6']) {
        $v6Candidate = if ($null -ne $oldMtu) { $oldMtu } else { [int]$defaults.desired_mtu_ipv6 }
        $v6 = [int](Get-ClampedInt -Value $v6Candidate -Min $MinMtuIPv6 -Max $MaxMtu)
        Add-Member -InputObject $cfg -MemberType NoteProperty -Name 'desired_mtu_ipv6' -Value $v6
        $changed = $true
    }

    foreach ($k in $defaults.Keys) {
        if (-not $cfg.PSObject.Properties[$k]) {
            Add-Member -InputObject $cfg -MemberType NoteProperty -Name $k -Value $defaults[$k]
            $changed = $true
        }
    }

    if ($changed) { Write-JsonFile -Path $ConfigPath -Data $cfg }
    return $cfg
}

function Initialize-StateStore {
    Initialize-AppDirectory
    $st = Read-JsonFile -Path $StatePath
    $defaults = Get-DefaultState

    if (-not $st) {
        Write-JsonFile -Path $StatePath -Data $defaults
        return [pscustomobject]$defaults
    }

    $changed = $false

    $oldMtu = $null
    try {
        if ($st.PSObject.Properties['desired_mtu']) {
            $oldMtu = [int]$st.desired_mtu
        }
    } catch {
        $oldMtu = $null
    }

    if (-not $st.PSObject.Properties['desired_mtu_ipv4']) {
        $v4 = if ($null -ne $oldMtu) { [int](Get-ClampedInt -Value $oldMtu -Min $MinMtuIPv4 -Max $MaxMtu) } else { [int]$defaults.desired_mtu_ipv4 }
        Add-Member -InputObject $st -MemberType NoteProperty -Name 'desired_mtu_ipv4' -Value $v4
        $changed = $true
    }

    if (-not $st.PSObject.Properties['desired_mtu_ipv6']) {
        $v6Candidate = if ($null -ne $oldMtu) { $oldMtu } else { [int]$defaults.desired_mtu_ipv6 }
        $v6 = [int](Get-ClampedInt -Value $v6Candidate -Min $MinMtuIPv6 -Max $MaxMtu)
        Add-Member -InputObject $st -MemberType NoteProperty -Name 'desired_mtu_ipv6' -Value $v6
        $changed = $true
    }

    foreach ($k in $defaults.Keys) {
        if (-not $st.PSObject.Properties[$k]) {
            Add-Member -InputObject $st -MemberType NoteProperty -Name $k -Value $defaults[$k]
            $changed = $true
        }
    }

    if ($changed) { Write-JsonFile -Path $StatePath -Data $st }
    return $st
}

function Get-Config {
    $cfg = Initialize-ConfigStore

    $desired4 = 1280
    $desired6 = 1280
    $interval = $DefaultCheckIntervalSeconds

    try {
        if ($cfg.PSObject.Properties['desired_mtu_ipv4']) {
            $desired4 = [int]$cfg.desired_mtu_ipv4
        } elseif ($cfg.PSObject.Properties['desired_mtu']) {
            $desired4 = [int]$cfg.desired_mtu
        }
    } catch {
        $desired4 = 1280
    }

    try {
        if ($cfg.PSObject.Properties['desired_mtu_ipv6']) {
            $desired6 = [int]$cfg.desired_mtu_ipv6
        } elseif ($cfg.PSObject.Properties['desired_mtu']) {
            $desired6 = [int]$cfg.desired_mtu
        }
    } catch {
        $desired6 = 1280
    }

    try { $interval = [int]$cfg.check_interval_seconds } catch { $interval = $DefaultCheckIntervalSeconds }

    $desired4 = [int](Get-ClampedInt -Value $desired4 -Min $MinMtuIPv4 -Max $MaxMtu)
    $desired6 = [int](Get-ClampedInt -Value $desired6 -Min $MinMtuIPv6 -Max $MaxMtu)
    $interval = [int](Get-ClampedInt -Value $interval -Min 10 -Max 86400)

    [pscustomobject]@{
        enabled = [bool]$cfg.enabled
        desired_mtu_ipv4 = $desired4
        desired_mtu_ipv6 = $desired6
        interface_match = if ($cfg.interface_match) { [string]$cfg.interface_match } else { 'Tailscale' }
        check_interval_seconds = $interval
    }
}

function Save-Config {
    param(
        [int]$DesiredMtuIPv4,
        [int]$DesiredMtuIPv6,
        [bool]$Enabled,
        [string]$InterfaceMatch,
        [int]$CheckIntervalSeconds
    )

    if ($DesiredMtuIPv4 -lt $MinMtuIPv4 -or $DesiredMtuIPv4 -gt $MaxMtu) {
        throw "Invalid IPv4 MTU: $DesiredMtuIPv4 (allowed: $MinMtuIPv4-$MaxMtu)"
    }

    if ($DesiredMtuIPv6 -lt $MinMtuIPv6 -or $DesiredMtuIPv6 -gt $MaxMtu) {
        throw "Invalid IPv6 MTU: $DesiredMtuIPv6 (allowed: $MinMtuIPv6-$MaxMtu)"
    }

    if ($CheckIntervalSeconds -lt 10) { $CheckIntervalSeconds = 10 }
    if ($CheckIntervalSeconds -gt 86400) { $CheckIntervalSeconds = 86400 }
    if ([string]::IsNullOrWhiteSpace($InterfaceMatch)) { $InterfaceMatch = 'Tailscale' }

    $cfg = [ordered]@{
        enabled = $Enabled
        desired_mtu_ipv4 = [int]$DesiredMtuIPv4
        desired_mtu_ipv6 = [int]$DesiredMtuIPv6
        interface_match = $InterfaceMatch
        check_interval_seconds = [int]$CheckIntervalSeconds
    }

    Write-JsonFile -Path $ConfigPath -Data $cfg
    return [pscustomobject]$cfg
}

function Update-State {
    param([hashtable]$Patch)

    return (Invoke-WithStateLock -ScriptBlock {
        $st = Initialize-StateStore
        $changed = $false

        foreach ($k in $Patch.Keys) {
            $newValue = $Patch[$k]

            if ($st.PSObject.Properties[$k]) {
                $currentValue = $st.$k

                if (-not [object]::Equals($currentValue, $newValue)) {
                    $st.$k = $newValue
                    $changed = $true
                }
            } else {
                Add-Member -InputObject $st -MemberType NoteProperty -Name $k -Value $newValue
                $changed = $true
            }
        }

        if ($changed) {
            Write-JsonFile -Path $StatePath -Data $st
        }

        return $st
    })
}

function New-ApplyRequestedEventSecurity {
    try {
        $security = New-Object System.Security.AccessControl.EventWaitHandleSecurity
        $world = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        $rights = [System.Security.AccessControl.EventWaitHandleRights]::Synchronize -bor [System.Security.AccessControl.EventWaitHandleRights]::Modify
        $rule = New-Object System.Security.AccessControl.EventWaitHandleAccessRule($world, $rights, [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
        return $security
    } catch {
        return $null
    }
}

function New-ApplyRequestedEventHandle {
    $createdNew = $false

    try {
        $security = New-ApplyRequestedEventSecurity
        if ($security) {
            return [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::AutoReset, $ApplyRequestedEventName, [ref]$createdNew, $security)
        }
    } catch {
    }

    try {
        return [System.Threading.EventWaitHandle]::OpenExisting($ApplyRequestedEventName)
    } catch {
        return $null
    }
}

function Set-ApplyRequestedEvent {
    $evt = $null

    try {
        $evt = New-ApplyRequestedEventHandle
        if ($evt) {
            [void]$evt.Set()
            return $true
        }
    } catch {
    } finally {
        if ($evt) {
            try { $evt.Dispose() } catch {}
        }
    }

    return $false
}

function Wait-ApplyRequestedEvent {
    param(
        [System.Threading.EventWaitHandle]$EventHandle,
        [int]$TimeoutMilliseconds
    )

    if ($TimeoutMilliseconds -lt 1) { $TimeoutMilliseconds = 1 }

    if (-not $EventHandle) {
        Start-Sleep -Milliseconds $TimeoutMilliseconds
        return $false
    }

    try {
        return [bool]$EventHandle.WaitOne($TimeoutMilliseconds)
    } catch {
        Start-Sleep -Milliseconds $TimeoutMilliseconds
        return $false
    }
}

function Clear-ApplyRequestedEvent {
    param([System.Threading.EventWaitHandle]$EventHandle)

    if (-not $EventHandle) { return }

    try {
        while ($EventHandle.WaitOne(0)) {
        }
    } catch {
    }
}

function Request-PendingApply {
    Update-State @{
        pending_apply = $true
        apply_requested_utc = Get-NowIsoUtc
    } | Out-Null
    [void](Set-ApplyRequestedEvent)
}

function Clear-PendingApply {
    Update-State @{ pending_apply = $false } | Out-Null
}

function Get-StateSafe {
    return (Invoke-WithStateLock -ScriptBlock {
        Initialize-StateStore
    })
}

function Get-ShortcutPath {
    $programs = [Environment]::GetFolderPath('CommonPrograms')
    if ([string]::IsNullOrWhiteSpace($programs)) {
        $programs = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
    }
    Join-Path $programs "$AppDisplayName.lnk"
}

function New-UiLauncherVbs {
    Initialize-AppDirectory
    $pwsh = Get-PowerShellExePath
    if (-not (Test-Path -LiteralPath $pwsh)) { throw 'PowerShell executable not found for UI launcher.' }
    if (-not (Test-Path -LiteralPath $ScriptDest)) { throw 'Installed script not found for UI launcher.' }

    $cmd = "`"$pwsh`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptDest`" -UI"
    $cmdEscaped = $cmd.Replace('"', '""')

    $vbs = @"
Set sh = CreateObject("WScript.Shell")
sh.Run "$cmdEscaped", 0, False
"@

    Set-Content -LiteralPath $UiLauncherVbsPath -Value $vbs -Encoding ASCII -Force
    return $UiLauncherVbsPath
}

function New-StartMenuShortcut {
    $shortcutPath = Get-ShortcutPath
    if (-not (Test-Path -LiteralPath $UiLauncherVbsPath)) {
        New-UiLauncherVbs | Out-Null
    }

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "$env:WINDIR\System32\wscript.exe"
    $shortcut.Arguments = "`"$UiLauncherVbsPath`""
    $shortcut.WorkingDirectory = $AppDir
    $iconForShortcut = if (Test-Path -LiteralPath $IconPath) { $IconPath } else { "$env:SystemRoot\System32\shell32.dll" }
    $iconIndex = if (Test-Path -LiteralPath $IconPath) { 0 } else { 220 }
    $shortcut.IconLocation = "$iconForShortcut,$iconIndex"
    $shortcut.Description = "Open $AppDisplayName"
    $shortcut.Save()
    return $shortcutPath
}

function Remove-StartMenuShortcut {
    $shortcutPath = Get-ShortcutPath
    if (Test-Path -LiteralPath $shortcutPath) {
        Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue
    }
}

function Copy-ScriptToAppDirectory {
    Initialize-AppDirectory
    $resolvedScriptPath = Get-ResolvedScriptPath

    try {
        $sourceFullPath = [System.IO.Path]::GetFullPath($resolvedScriptPath)
        $destFullPath = [System.IO.Path]::GetFullPath($ScriptDest)

        if ([string]::Equals($sourceFullPath, $destFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $ScriptDest
        }
    } catch {
    }

    Copy-Item -LiteralPath $resolvedScriptPath -Destination $ScriptDest -Force -ErrorAction Stop
    return $ScriptDest
}

function Test-ExeLooksValid {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            if ($fs.Length -lt 2) { return $false }
            $b1 = $fs.ReadByte()
            $b2 = $fs.ReadByte()
            return (($b1 -eq 77) -and ($b2 -eq 90))
        } finally {
            $fs.Dispose()
        }
    } catch {
        return $false
    }
}

function Install-NssmBinary {
    Initialize-AppDirectory

    if (Test-Path -LiteralPath $NssmPath) {
        try {
            $existing = Get-Item -LiteralPath $NssmPath -ErrorAction Stop
            if ($existing.Length -gt 0) {
                return $NssmPath
            }
        } catch {
            return $NssmPath
        }
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    } catch {
    }

    $tmp = "$NssmPath.download"
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

    try {
        Invoke-WebRequest -Uri $NssmDownloadUrl -OutFile $tmp -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to download nssm.exe from $NssmDownloadUrl. $($_.Exception.Message)"
    }

    if (-not (Test-ExeLooksValid -Path $tmp)) {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw 'Downloaded nssm.exe is invalid.'
    }

    Move-Item -LiteralPath $tmp -Destination $NssmPath -Force
    return $NssmPath
}

function Get-PowerShellExePath {
    Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
}

function Get-ServiceStatusText {
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        return [string]$svc.Status
    } catch {
        return 'Not installed'
    }
}

function Wait-ServiceGone {
    param(
        [string]$Name,
        [int]$TimeoutSeconds = 20
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc) { return $true }
        Start-Sleep -Milliseconds 500
    }

    return $false
}

function Start-BackgroundServiceSafe {
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        return $true
    } catch {
        try {
            if (Test-Path -LiteralPath $NssmPath) {
                & $NssmPath start $ServiceName *> $null
                return ($LASTEXITCODE -eq 0)
            }
        } catch {
        }
        return $false
    }
}

function Stop-BackgroundServiceSafe {
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        return $true
    } catch {
        try {
            if (Test-Path -LiteralPath $NssmPath) {
                & $NssmPath stop $ServiceName *> $null
                return ($LASTEXITCODE -eq 0)
            }
        } catch {
        }
        return $false
    }
}

function Set-ServiceRecoveryOptions {
    param([string]$Name)

    & sc.exe failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/10000 *> $null
    & sc.exe failureflag $Name 1 *> $null
}


function Remove-EmptyServiceLogFiles {
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) { return }

        Get-ChildItem -LiteralPath $LogDir -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Length -eq 0 -and
                ($_.Name -like 'service.out*.log' -or $_.Name -like 'service.err*.log')
            } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {
    }
}


function Set-TailscaleMtuServiceStartup {
    & sc.exe config $ServiceName start= auto *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to set automatic startup.' }

    $tailscaleService = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
    if ($tailscaleService) {
        & sc.exe config $ServiceName depend= Tailscale *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to set Tailscale service dependency.' }
    }
}

function Install-BackgroundService {
    $nssm = Install-NssmBinary
    $pwsh = Get-PowerShellExePath
    if (-not (Test-Path -LiteralPath $pwsh)) { throw "PowerShell executable not found at $pwsh" }

    Remove-EmptyServiceLogFiles
    $psArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptDest`" -RunLoop"

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        & $nssm stop $ServiceName *> $null
        Start-Sleep -Milliseconds 300
        & $nssm remove $ServiceName confirm *> $null
        if (-not (Wait-ServiceGone -Name $ServiceName -TimeoutSeconds 20)) {
            & sc.exe delete $ServiceName *> $null
            if (-not (Wait-ServiceGone -Name $ServiceName -TimeoutSeconds 20)) {
                throw 'Service removal is still pending. Close Services MMC or reboot, then run Install or Repair again.'
            }
        }
    }

    & $nssm install $ServiceName $pwsh $psArgs *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to install the service.' }

    & $nssm set $ServiceName DisplayName $ServiceDisplayName *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set DisplayName.' }

    & $nssm set $ServiceName Description $ServiceDescription *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set Description.' }

    & $nssm set $ServiceName Start SERVICE_AUTO_START *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set startup type.' }

    Set-TailscaleMtuServiceStartup

    & $nssm set $ServiceName ObjectName LocalSystem *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set LocalSystem.' }

    & $nssm set $ServiceName AppDirectory $AppDir *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set AppDirectory.' }

    & $nssm set $ServiceName AppThrottle 1500 *> $null
    & $nssm set $ServiceName AppExit Default Restart *> $null

    Set-ServiceRecoveryOptions -Name $ServiceName

    & $nssm start $ServiceName *> $null
    if ($LASTEXITCODE -ne 0) {
        try { Start-Service -Name $ServiceName -ErrorAction Stop } catch {}
    }

    $finalStatus = Get-ServiceStatusText
    if ($finalStatus -ne 'Running') {
        throw "Service installed but is not running. Current status: $finalStatus"
    }

    Remove-EmptyServiceLogFiles
}

function Uninstall-BackgroundService {
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $existingService) { return }

    if (Test-Path -LiteralPath $NssmPath) {
        & $NssmPath stop $ServiceName *> $null
        Start-Sleep -Milliseconds 500
        & $NssmPath remove $ServiceName confirm *> $null
    } else {
        try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        & sc.exe delete $ServiceName *> $null
    }

    if (-not (Wait-ServiceGone -Name $ServiceName -TimeoutSeconds 20)) {
        & sc.exe delete $ServiceName *> $null
        [void](Wait-ServiceGone -Name $ServiceName -TimeoutSeconds 20)
    }
}

function Get-TailscaleInterface {
    param([string]$MatchText = 'Tailscale')

    $regex = [regex]::Escape($MatchText)
    $adapters = @()

    try {
        $adapters = Get-NetAdapter -IncludeHidden -ErrorAction Stop
    } catch {
        try {
            $adapters = Get-NetAdapter -ErrorAction Stop
        } catch {
            $adapters = @()
        }
    }

    if ($adapters.Count -gt 0) {
        $candidates = $adapters | Where-Object {
            ($_.Name -match '(?i)tailscale') -or
            ($_.InterfaceDescription -match '(?i)tailscale') -or
            ($MatchText -and (($_.Name -match "(?i)$regex") -or ($_.InterfaceDescription -match "(?i)$regex")))
        }

        if ($candidates) {
            $best = $candidates | Sort-Object `
                @{Expression = { if ($_.Status -eq 'Up') { 0 } else { 1 } }}, `
                @{Expression = { $_.Name }} | Select-Object -First 1

            return [pscustomobject]@{
                Alias = $best.Name
                Description = $best.InterfaceDescription
                Status = [string]$best.Status
                InterfaceIndex = $best.ifIndex
            }
        }
    }

    try {
        $rows = Get-NetIPInterface -ErrorAction Stop | Where-Object {
            $_.InterfaceAlias -match '(?i)tailscale' -or
            ($MatchText -and $_.InterfaceAlias -match "(?i)$regex")
        }
        if ($rows) {
            $best2 = $rows | Sort-Object `
                @{Expression = { if ($_.ConnectionState -eq 'Connected') { 0 } else { 1 } }}, `
                @{Expression = { $_.InterfaceAlias }} | Select-Object -First 1

            return [pscustomobject]@{
                Alias = $best2.InterfaceAlias
                Description = $null
                Status = [string]$best2.ConnectionState
                InterfaceIndex = $best2.InterfaceIndex
            }
        }
    } catch {
    }

    return $null
}

function Get-InterfaceMtu {
    param(
        [string]$Alias,
        [ValidateSet('IPv4','IPv6')]
        [string]$AddressFamily
    )
    try {
        $rows = Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily $AddressFamily -ErrorAction Stop
        if (-not $rows) { return $null }
        $row = $rows | Select-Object -First 1
        if ($row.PSObject.Properties['NlMtuBytes'] -and $null -ne $row.NlMtuBytes) { return [int]$row.NlMtuBytes }
        if ($row.PSObject.Properties['NlMtu'] -and $null -ne $row.NlMtu) { return [int]$row.NlMtu }
        return $null
    } catch {
        return $null
    }
}

function Set-InterfaceMtuFamily {
    param(
        [string]$Alias,
        [ValidateSet('IPv4','IPv6')]
        [string]$AddressFamily,
        [int]$Mtu
    )

    $errors = New-Object System.Collections.Generic.List[string]

    try {
        $rows = Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily $AddressFamily -ErrorAction Stop
        foreach ($r in $rows) {
            try {
                Set-NetIPInterface -InterfaceIndex $r.InterfaceIndex -AddressFamily $AddressFamily -NlMtuBytes $Mtu -ErrorAction Stop | Out-Null
            } catch {
                $errors.Add("$AddressFamily Set-NetIPInterface: $($_.Exception.Message)")
            }
        }
    } catch {
        $errors.Add("$AddressFamily Get-NetIPInterface: $($_.Exception.Message)")
    }

    try {
        $proto = if ($AddressFamily -eq 'IPv4') { 'ipv4' } else { 'ipv6' }
        $netshOut = & netsh interface $proto set subinterface "$Alias" "mtu=$Mtu" "store=persistent" 2>&1
        if ($LASTEXITCODE -ne 0 -and $netshOut) {
            $errors.Add("$AddressFamily netsh: $($netshOut | Out-String)")
        }
    } catch {
        $errors.Add("$AddressFamily netsh: $($_.Exception.Message)")
    }

    $verify = Get-InterfaceMtu -Alias $Alias -AddressFamily $AddressFamily
    if ($verify -ne $Mtu) {
        if ($errors.Count -gt 0) {
            throw ($errors -join ' | ')
        }
        throw "$AddressFamily MTU verify failed. Expected $Mtu, got $verify."
    }

    return [int]$verify
}

function Set-InterfaceMtuDual {
    param(
        [string]$Alias,
        [int]$MtuIPv4,
        [int]$MtuIPv6
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $verify4 = $null
    $verify6 = $null

    try {
        $verify4 = Set-InterfaceMtuFamily -Alias $Alias -AddressFamily IPv4 -Mtu $MtuIPv4
    } catch {
        $errors.Add($_.Exception.Message)
    }

    try {
        $verify6 = Set-InterfaceMtuFamily -Alias $Alias -AddressFamily IPv6 -Mtu $MtuIPv6
    } catch {
        $errors.Add($_.Exception.Message)
    }

    if ($errors.Count -gt 0) {
        throw ($errors -join ' | ')
    }

    [pscustomobject]@{
        IPv4 = $verify4
        IPv6 = $verify6
    }
}

function Test-ApplyNow {
    param(
        [pscustomobject]$Cfg,
        [pscustomobject]$State
    )

    $forceApply = $false
    try { $forceApply = [bool]$State.pending_apply } catch { $forceApply = $false }
    if ($forceApply) { return $true }

    $lastCheck = ConvertTo-UtcDateTimeSafe -Value $State.last_check_utc
    if (-not $lastCheck) { return $true }

    $elapsed = ([DateTime]::UtcNow - $lastCheck).TotalSeconds
    return ($elapsed -ge [double]$Cfg.check_interval_seconds)
}

function Invoke-Apply {
    $cfg = Get-Config
    $st = Get-StateSafe

    if (-not (Test-ApplyNow -Cfg $cfg -State $st)) {
        return [pscustomobject]@{
            Ok = $true
            Changed = $false
            Reason = 'throttled'
        }
    }

    $now = Get-NowIsoUtc
    $forceApply = $false
    try { $forceApply = [bool]$st.pending_apply } catch { $forceApply = $false }

    if (-not $cfg.enabled) {
        Update-State @{
            pending_apply = $false
            last_result = 'disabled'
            last_error = $null
            last_check_utc = $now
            desired_mtu_ipv4 = $cfg.desired_mtu_ipv4
            desired_mtu_ipv6 = $cfg.desired_mtu_ipv6
        } | Out-Null

        return [pscustomobject]@{
            Ok = $true
            Changed = $false
            Reason = 'disabled'
        }
    }

    $iface = Get-TailscaleInterface -MatchText $cfg.interface_match
    if (-not $iface) {
        Update-State @{
            pending_apply = $forceApply
            last_result = 'interface_not_found'
            last_error = $null
            last_check_utc = $now
            desired_mtu_ipv4 = $cfg.desired_mtu_ipv4
            desired_mtu_ipv6 = $cfg.desired_mtu_ipv6
            detected_interface = $null
            current_mtu_ipv4 = $null
            current_mtu_ipv6 = $null
        } | Out-Null

        return [pscustomobject]@{
            Ok = $false
            Changed = $false
            Reason = 'interface_not_found'
        }
    }

    $current4 = Get-InterfaceMtu -Alias $iface.Alias -AddressFamily IPv4
    $current6 = Get-InterfaceMtu -Alias $iface.Alias -AddressFamily IPv6
    $changed = $false

    try {
        if ($forceApply -or ($current4 -ne $cfg.desired_mtu_ipv4) -or ($current6 -ne $cfg.desired_mtu_ipv6)) {
            $set = Set-InterfaceMtuDual -Alias $iface.Alias -MtuIPv4 $cfg.desired_mtu_ipv4 -MtuIPv6 $cfg.desired_mtu_ipv6
            $current4 = $set.IPv4
            $current6 = $set.IPv6
            $changed = $true
        }

        $latestCfg = Get-Config
        $latestSt = Get-StateSafe
        $applyRequestUtcAtStart = $null
        try { $applyRequestUtcAtStart = [string]$st.apply_requested_utc } catch { $applyRequestUtcAtStart = $null }
        $applyRequestUtcNow = $null
        try { $applyRequestUtcNow = [string]$latestSt.apply_requested_utc } catch { $applyRequestUtcNow = $null }
        $requestChangedDuringApply = (-not [string]::Equals($applyRequestUtcNow, $applyRequestUtcAtStart, [System.StringComparison]::Ordinal))
        $configChangedDuringApply = (($latestCfg.enabled -ne $cfg.enabled) -or ($latestCfg.desired_mtu_ipv4 -ne $cfg.desired_mtu_ipv4) -or ($latestCfg.desired_mtu_ipv6 -ne $cfg.desired_mtu_ipv6) -or (-not [string]::Equals([string]$latestCfg.interface_match, [string]$cfg.interface_match, [System.StringComparison]::OrdinalIgnoreCase)))
        $remainPending = ($requestChangedDuringApply -or $configChangedDuringApply)

        $patch = @{
            pending_apply = $remainPending
            last_result = if ($changed) { 'applied' } else { 'already_ok' }
            last_error = $null
            last_check_utc = $now
            desired_mtu_ipv4 = $latestCfg.desired_mtu_ipv4
            desired_mtu_ipv6 = $latestCfg.desired_mtu_ipv6
            detected_interface = $iface.Alias
            current_mtu_ipv4 = $current4
            current_mtu_ipv6 = $current6
        }

        if ($changed) {
            $patch.last_apply_utc = $now
        }

        Update-State $patch | Out-Null

        return [pscustomobject]@{
            Ok = $true
            Changed = $changed
            Reason = if ($changed) { 'applied' } else { 'already_ok' }
        }
    } catch {
        Update-State @{
            pending_apply = $false
            last_result = 'error'
            last_error = $_.Exception.Message
            last_check_utc = $now
            desired_mtu_ipv4 = $cfg.desired_mtu_ipv4
            desired_mtu_ipv6 = $cfg.desired_mtu_ipv6
            detected_interface = $iface.Alias
            current_mtu_ipv4 = $current4
            current_mtu_ipv6 = $current6
        } | Out-Null

        return [pscustomobject]@{
            Ok = $false
            Changed = $false
            Reason = 'error'
            Error = $_.Exception.Message
        }
    }
}

function Get-ServiceLoopSleepMilliseconds {
    param(
        [pscustomobject]$Cfg,
        [pscustomobject]$State,
        [DateTime]$NextHeartbeat
    )

    $now = [DateTime]::UtcNow
    $interval = $DefaultCheckIntervalSeconds
    try { $interval = [int]$Cfg.check_interval_seconds } catch { $interval = $DefaultCheckIntervalSeconds }
    if ($interval -lt 10) { $interval = 10 }

    $pending = $false
    try { $pending = [bool]$State.pending_apply } catch { $pending = $false }
    if ($pending) { return $LoopTickMilliseconds }

    $lastCheck = ConvertTo-UtcDateTimeSafe -Value $State.last_check_utc
    if (-not $lastCheck) { return $LoopTickMilliseconds }

    $secondsUntilCheck = $interval - ($now - $lastCheck).TotalSeconds
    if ($secondsUntilCheck -le 0) { return $LoopTickMilliseconds }

    $secondsUntilHeartbeat = ($NextHeartbeat - $now).TotalSeconds
    if ($secondsUntilHeartbeat -le 0) { return $LoopTickMilliseconds }

    $secondsUntilNextWork = [Math]::Min($secondsUntilCheck, $secondsUntilHeartbeat)
    $ms = [int]([Math]::Ceiling($secondsUntilNextWork * 1000))
    if ($ms -lt $LoopTickMilliseconds) { return $LoopTickMilliseconds }
    return $ms
}

function Invoke-RunLoop {
    $applyEvent = New-ApplyRequestedEventHandle

    try {
        $startupRequestUtc = Get-NowIsoUtc
        Update-State @{
            pending_apply = $true
            apply_requested_utc = $startupRequestUtc
            service_heartbeat_utc = $startupRequestUtc
        } | Out-Null

        $nextHeartbeat = [DateTime]::UtcNow

        while ($true) {
            $sleepMilliseconds = $LoopTickMilliseconds

            try {
                $cfg = Get-Config
                $st = Get-StateSafe
                $nowDt = [DateTime]::UtcNow

                if ($nowDt -ge $nextHeartbeat) {
                    $st = Update-State @{ service_heartbeat_utc = $nowDt.ToString('o') }
                    $nextHeartbeat = $nowDt.AddSeconds($HeartbeatWriteSeconds)
                }

                if ([bool]$cfg.enabled) {
                    try {
                        $tailscaleSvc = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
                        if ($tailscaleSvc -and $tailscaleSvc.Status -ne 'Running') {
                            Update-State @{
                                pending_apply = $true
                                last_result = 'waiting_for_tailscale_service'
                                last_error = $null
                            } | Out-Null

                            $wasSignaled = Wait-ApplyRequestedEvent -EventHandle $applyEvent -TimeoutMilliseconds $LoopTickMilliseconds
                            if ($wasSignaled) { Update-State @{ pending_apply = $true } | Out-Null }
                            continue
                        }
                    } catch {
                    }

                    $iface = Get-TailscaleInterface -MatchText $cfg.interface_match
                    if (-not $iface) {
                        Update-State @{
                            pending_apply = $true
                            last_result = 'waiting_for_tailscale_interface'
                            last_error = $null
                            detected_interface = $null
                            current_mtu_ipv4 = $null
                            current_mtu_ipv6 = $null
                        } | Out-Null

                        $wasSignaled = Wait-ApplyRequestedEvent -EventHandle $applyEvent -TimeoutMilliseconds $LoopTickMilliseconds
                        if ($wasSignaled) { Update-State @{ pending_apply = $true } | Out-Null }
                        continue
                    }
                }

                $st = Get-StateSafe

                if (Test-ApplyNow -Cfg $cfg -State $st) {
                    Invoke-Apply | Out-Null
                    Clear-ApplyRequestedEvent -EventHandle $applyEvent
                    $postApplyState = Get-StateSafe
                    if ([bool]$postApplyState.pending_apply) {
                        $sleepMilliseconds = $LoopTickMilliseconds
                    } else {
                        $sleepMilliseconds = Get-ServiceLoopSleepMilliseconds -Cfg $cfg -State $postApplyState -NextHeartbeat $nextHeartbeat
                    }
                } else {
                    $sleepMilliseconds = Get-ServiceLoopSleepMilliseconds -Cfg $cfg -State $st -NextHeartbeat $nextHeartbeat
                }
            } catch {
                try {
                    Update-State @{
                        last_result = 'error'
                        last_error = $_.Exception.Message
                    } | Out-Null
                } catch {
                }

                $sleepMilliseconds = $MaxIdleSleepMilliseconds
            }

            $wasSignaled = Wait-ApplyRequestedEvent -EventHandle $applyEvent -TimeoutMilliseconds $sleepMilliseconds
            if ($wasSignaled) {
                Update-State @{
                    pending_apply = $true
                    apply_requested_utc = Get-NowIsoUtc
                } | Out-Null
            }
        }
    } finally {
        if ($applyEvent) {
            try { $applyEvent.Dispose() } catch {}
        }
    }
}


function Get-ServiceHeartbeatStatus {
    param(
        [string]$ServiceStatus,
        [string]$HeartbeatUtc
    )

    if ($ServiceStatus -ne 'Running') { return 'not_running' }
    if ([string]::IsNullOrWhiteSpace($HeartbeatUtc)) { return 'missing' }

    $dt = ConvertTo-UtcDateTimeSafe -Value $HeartbeatUtc
    if (-not $dt) { return 'invalid' }

    $ageSeconds = ([DateTime]::UtcNow - $dt).TotalSeconds
    if ($ageSeconds -le 180) { return 'fresh' }
    return 'stale'
}

function Get-ServiceHeartbeatAgeSeconds {
    param([string]$HeartbeatUtc)
    $dt = ConvertTo-UtcDateTimeSafe -Value $HeartbeatUtc
    if (-not $dt) { return $null }
    return [int]([Math]::Max(0, ([DateTime]::UtcNow - $dt).TotalSeconds))
}

function Get-StatusObject {
    $cfg = Get-Config
    $st = Get-StateSafe
    $svcStatus = Get-ServiceStatusText
    $iface = Get-TailscaleInterface -MatchText $cfg.interface_match
    $cur4 = $null
    $cur6 = $null
    if ($iface) {
        $cur4 = Get-InterfaceMtu -Alias $iface.Alias -AddressFamily IPv4
        $cur6 = Get-InterfaceMtu -Alias $iface.Alias -AddressFamily IPv6
    }

    $heartbeatStatus = Get-ServiceHeartbeatStatus -ServiceStatus $svcStatus -HeartbeatUtc ([string]$st.service_heartbeat_utc)
    $heartbeatAge = Get-ServiceHeartbeatAgeSeconds -HeartbeatUtc ([string]$st.service_heartbeat_utc)
    $serviceNeedsAttention = ($svcStatus -eq 'Running' -and $heartbeatStatus -in @('stale', 'missing', 'invalid'))
    $applyBlockedByStaleService = ([bool]$st.pending_apply -and $serviceNeedsAttention)

    $serviceStartMode = $null
    $serviceDependencies = $null
    $tailscaleServiceStatus = $null

    try {
        $svcInfo = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if ($svcInfo.PSObject.Properties['DelayedAutoStart'] -and $svcInfo.DelayedAutoStart) {
            $serviceStartMode = 'Automatic (Delayed Start)'
        } else {
            $serviceStartMode = [string]$svcInfo.StartMode
        }

        try { $serviceDependencies = ($svcInfo.Dependencies -join ', ') } catch { $serviceDependencies = $null }
    } catch {
        $serviceStartMode = $null
        $serviceDependencies = $null
    }

    try {
        $tailscaleSvc = Get-Service -Name 'Tailscale' -ErrorAction Stop
        $tailscaleServiceStatus = [string]$tailscaleSvc.Status
    } catch {
        $tailscaleServiceStatus = $null
    }

    [pscustomobject]@{
        version = $AppVersion
        service_name = $ServiceName
        service_status = $svcStatus
        service_start_mode = $serviceStartMode
        service_dependencies = $serviceDependencies
        tailscale_service_status = $tailscaleServiceStatus
        app_dir = $AppDir
        script_path = $ScriptDest
        config_path = $ConfigPath
        state_path = $StatePath
        nssm_path = $NssmPath
        installed = (Test-Path -LiteralPath $ScriptDest)
        service_installed = ($svcStatus -ne 'Not installed')
        enabled = $cfg.enabled
        desired_mtu_ipv4 = $cfg.desired_mtu_ipv4
        desired_mtu_ipv6 = $cfg.desired_mtu_ipv6
        check_interval_seconds = $cfg.check_interval_seconds
        interface_match = $cfg.interface_match
        detected_interface = if ($iface) { $iface.Alias } else { $null }
        current_mtu_ipv4 = $cur4
        current_mtu_ipv6 = $cur6
        pending_apply = $st.pending_apply
        last_result = $st.last_result
        last_error = $st.last_error
        last_check_utc = $st.last_check_utc
        last_apply_utc = $st.last_apply_utc
        service_heartbeat_utc = $st.service_heartbeat_utc
        service_heartbeat_status = $heartbeatStatus
        service_heartbeat_age_seconds = $heartbeatAge
        service_needs_attention = $serviceNeedsAttention
        apply_blocked_by_stale_service = $applyBlockedByStaleService
    }
}
function Write-StatusText {
    $s = Get-StatusObject
    @(
        "Version: $($s.version)"
        "Service Name: $($s.service_name)"
        "Service Status: $($s.service_status)"
        "Service Start Mode: $($s.service_start_mode)"
        "Service Dependencies: $($s.service_dependencies)"
        "Tailscale Service Status: $($s.tailscale_service_status)"
        "AppDir: $($s.app_dir)"
        "Script: $($s.script_path)"
        "Config: $($s.config_path)"
        "State: $($s.state_path)"
        "NSSM: $($s.nssm_path)"
        "Enabled: $($s.enabled)"
        "Desired MTU IPv4: $($s.desired_mtu_ipv4)"
        "Desired MTU IPv6: $($s.desired_mtu_ipv6)"
        "Check Interval (s): $($s.check_interval_seconds)"
        "Interface Match: $($s.interface_match)"
        "Detected Interface: $($s.detected_interface)"
        "Current MTU IPv4: $($s.current_mtu_ipv4)"
        "Current MTU IPv6: $($s.current_mtu_ipv6)"
        "Pending Apply: $($s.pending_apply)"
        "Last Result: $($s.last_result)"
        "Last Error: $($s.last_error)"
        "Last Check UTC: $($s.last_check_utc)"
        "Last Apply UTC: $($s.last_apply_utc)"
        "Service Heartbeat UTC: $($s.service_heartbeat_utc)"
        "Service Heartbeat Status: $($s.service_heartbeat_status)"
        "Service Needs Attention: $($s.service_needs_attention)"
        "Apply Blocked By Stale Service: $($s.apply_blocked_by_stale_service)"
    ) -join [Environment]::NewLine
}

function Write-StatusJson {
    $s = Get-StatusObject
    return ($s | ConvertTo-Json -Depth 20 -Compress)
}

function Start-MtuGuiFromShortcut {
    try {
        $shortcut = Get-ShortcutPath
        if (-not (Test-Path -LiteralPath $shortcut)) { return $false }
        Start-Process -FilePath $shortcut | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Start-MtuGuiProcess {
    try {
        if (Test-Path -LiteralPath $UiLauncherVbsPath) {
            Start-Process -FilePath "$env:WINDIR\System32\wscript.exe" -ArgumentList "`"$UiLauncherVbsPath`"" -WindowStyle Hidden | Out-Null
            return $true
        }

        $shortcut = Get-ShortcutPath
        if (Test-Path -LiteralPath $shortcut) {
            Start-Process -FilePath $shortcut | Out-Null
            return $true
        }

        $pwsh = Get-PowerShellExePath
        if (-not (Test-Path -LiteralPath $pwsh)) { return $false }
        $targetScript = $null
        if ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath)) {
            $targetScript = $ScriptPath
        } elseif (Test-Path -LiteralPath $ScriptDest) {
            $targetScript = $ScriptDest
        } else {
            try {
                $targetScript = Get-ResolvedScriptPath
            } catch {
                $targetScript = $null
            }
        }
        if ([string]::IsNullOrWhiteSpace($targetScript)) { return $false }

        $uiArgs = @(
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-WindowStyle', 'Hidden'
            '-File', "`"$targetScript`""
            '-UI'
        )

        Start-Process -FilePath $pwsh -ArgumentList ($uiArgs -join ' ') -WindowStyle Hidden | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Start-RepairProcessFromUi {
    param([switch]$ReopenUi)

    try {
        $pwsh = Get-PowerShellExePath
        if (-not (Test-Path -LiteralPath $pwsh)) { return $false }

        $repairScript = $null
        if (Test-Path -LiteralPath $ScriptDest) {
            $repairScript = $ScriptDest
        } elseif ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath)) {
            $repairScript = $ScriptPath
        } else {
            $repairScript = Get-ResolvedScriptPath
        }

        if ([string]::IsNullOrWhiteSpace($repairScript) -or -not (Test-Path -LiteralPath $repairScript)) { return $false }

        $repairArgs = @(
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-WindowStyle', 'Hidden'
            '-File', "`"$repairScript`""
            '-Install'
        )

        if (-not $ReopenUi) {
            $repairArgs += '-NoOpenUi'
        }

        Start-Process -FilePath $pwsh -ArgumentList ($repairArgs -join ' ') -Verb RunAs -WindowStyle Hidden | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Start-UpdateProcessFromUi {
    param([switch]$ReopenUi)

    $pwsh = Get-PowerShellExePath
    if (-not (Test-Path -LiteralPath $pwsh)) {
        throw "PowerShell executable not found: $pwsh"
    }

    $tmpBase = "Tailscale-MTU-Update-" + [guid]::NewGuid().ToString('N')
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) $tmpBase
    $tmpUpdater = Join-Path $tmpDir 'update.ps1'
    $tmpLog = Join-Path $tmpDir 'update.log'

    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    $updater = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Owner = 'luizbizzio'
$Repo = 'tailscale-mtu'
$ReleaseBaseUrl = "https://github.com/$Owner/$Repo/releases/latest/download"
$AppScriptUrl = "$ReleaseBaseUrl/tailscale-mtu.ps1"
$IconUrl = "$ReleaseBaseUrl/tailscale-mtu.ico"
$NssmUrl = "$ReleaseBaseUrl/nssm.exe"

function Write-UpdateLog {
    param([string]$Message)
    $line = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] $Message"
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function Get-PowerShellExePath {
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $powershell) { return $powershell }
    return 'powershell.exe'
}

function Test-ExeLooksValid {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            if ($fs.Length -lt 2) { return $false }
            $b1 = $fs.ReadByte()
            $b2 = $fs.ReadByte()
            return (($b1 -eq 77) -and ($b2 -eq 90))
        } finally {
            $fs.Dispose()
        }
    } catch {
        return $false
    }
}

try {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    } catch {
    }

    Write-UpdateLog 'Update bootstrap started.'

    $appDir = Join-Path $env:ProgramData 'TailscaleMTU'
    $logDir = Join-Path $appDir 'logs'
    $destScriptPath = Join-Path $appDir 'tailscale-mtu.ps1'
    $destIconPath = Join-Path $appDir 'tailscale-mtu.ico'
    $destNssmPath = Join-Path $appDir 'nssm.exe'

    if (-not (Test-Path -LiteralPath $appDir)) {
        New-Item -ItemType Directory -Path $appDir -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $downloadDir = Join-Path ([System.IO.Path]::GetTempPath()) ("Tailscale-MTU-Assets-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null

    $tmpScript = Join-Path $downloadDir 'tailscale-mtu.ps1'
    $tmpIcon = Join-Path $downloadDir 'tailscale-mtu.ico'
    $tmpNssm = Join-Path $downloadDir 'nssm.exe'

    Write-UpdateLog 'Downloading tailscale-mtu.ps1 from latest release.'
    Invoke-WebRequest -Uri $AppScriptUrl -OutFile $tmpScript -UseBasicParsing -ErrorAction Stop

    Write-UpdateLog 'Downloading tailscale-mtu.ico from latest release.'
    Invoke-WebRequest -Uri $IconUrl -OutFile $tmpIcon -UseBasicParsing -ErrorAction Stop

    Write-UpdateLog 'Downloading nssm.exe from latest release.'
    Invoke-WebRequest -Uri $NssmUrl -OutFile $tmpNssm -UseBasicParsing -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $tmpScript)) {
        throw 'Downloaded tailscale-mtu.ps1 was not found.'
    }

    if (-not (Test-Path -LiteralPath $tmpIcon)) {
        throw 'Downloaded tailscale-mtu.ico was not found.'
    }

    if (-not (Test-ExeLooksValid -Path $tmpNssm)) {
        throw 'Downloaded nssm.exe is missing or invalid.'
    }

    Write-UpdateLog 'Staging assets to ProgramData.'
    Copy-Item -LiteralPath $tmpScript -Destination $destScriptPath -Force
    Copy-Item -LiteralPath $tmpIcon -Destination $destIconPath -Force

    if (Test-Path -LiteralPath $destNssmPath) {
        Write-UpdateLog 'Existing nssm.exe found. Keeping it because the service may be using it.'
    } else {
        Write-UpdateLog 'Staging nssm.exe.'
        Copy-Item -LiteralPath $tmpNssm -Destination $destNssmPath -Force
        if (-not (Test-ExeLooksValid -Path $destNssmPath)) {
            throw "Installed nssm.exe is missing or invalid: $destNssmPath"
        }
    }

    if (-not (Test-Path -LiteralPath $destScriptPath)) {
        throw "Installed script was not staged: $destScriptPath"
    }

    if (-not (Test-Path -LiteralPath $destIconPath)) {
        throw "Installed icon was not staged: $destIconPath"
    }

    Write-UpdateLog 'Running local install/repair with -NoOpenUi.'
    $pwsh = Get-PowerShellExePath
    $installArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $destScriptPath,
        '-Install',
        '-NoOpenUi'
    )

    & $pwsh @installArgs
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        throw "Install/repair exited with code $exitCode."
    }

    Write-UpdateLog 'Update completed successfully.'
    exit 0
} catch {
    Write-UpdateLog ("ERROR: " + $_.Exception.Message)
    exit 1
} finally {
    try {
        if ($downloadDir -and (Test-Path -LiteralPath $downloadDir)) {
            Remove-Item -LiteralPath $downloadDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
    }
}
'@

    Set-Content -LiteralPath $tmpUpdater -Value $updater -Encoding UTF8 -Force

    $updateArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-WindowStyle', 'Hidden',
        '-File', "`"$tmpUpdater`"",
        '-LogPath', "`"$tmpLog`""
    )

    if ($ReopenUi) {
        $process = Start-Process -FilePath $pwsh -ArgumentList ($updateArgs -join ' ') -Verb RunAs -WindowStyle Hidden -Wait -PassThru

        if ($null -eq $process) {
            throw 'Update process did not start.'
        }

        if ($process.ExitCode -ne 0) {
            $logText = ''
            try {
                if (Test-Path -LiteralPath $tmpLog) {
                    $logText = Get-Content -LiteralPath $tmpLog -Raw -Encoding UTF8 -ErrorAction Stop
                }
            } catch {
                $logText = ''
            }

            if ([string]::IsNullOrWhiteSpace($logText)) {
                throw "Updater exited with code $($process.ExitCode). No update log was produced."
            }

            throw "Updater exited with code $($process.ExitCode). Log: $logText"
        }

        Start-Sleep -Milliseconds 700

        $installedScript = Join-Path $AppDir 'tailscale-mtu.ps1'
        if (-not (Test-Path -LiteralPath $installedScript)) {
            throw "Installed script not found after update: $installedScript"
        }

        $uiArgs = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-WindowStyle', 'Hidden',
            '-File', "`"$installedScript`"",
            '-UI'
        )

        Start-Process -FilePath $pwsh -ArgumentList ($uiArgs -join ' ') -WindowStyle Hidden | Out-Null
        return $true
    }

    Start-Process -FilePath $pwsh -ArgumentList ($updateArgs -join ' ') -Verb RunAs -WindowStyle Hidden | Out-Null
    return $true
}

function ConvertFrom-VersionTag {
    param([string]$Tag)
    if ([string]::IsNullOrWhiteSpace($Tag)) { return '' }
    return $Tag.Trim().TrimStart('v', 'V')
}

function Compare-VersionText {
    param(
        [string]$A,
        [string]$B
    )

    $aClean = ConvertFrom-VersionTag -Tag $A
    $bClean = ConvertFrom-VersionTag -Tag $B

    try {
        $av = [version]$aClean
        $bv = [version]$bClean
        return $av.CompareTo($bv)
    } catch {
        return [string]::Compare($aClean, $bClean, [System.StringComparison]::OrdinalIgnoreCase)
    }
}

function Get-LatestReleaseTag {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    } catch {
    }

    $headers = @{ 'User-Agent' = 'Tailscale-MTU' }
    $release = Invoke-RestMethod -Uri $GitHubLatestReleaseApiUrl -Headers $headers -UseBasicParsing -ErrorAction Stop
    if (-not $release -or [string]::IsNullOrWhiteSpace([string]$release.tag_name)) {
        throw 'Latest GitHub release did not return a tag_name.'
    }

    return [string]$release.tag_name
}

function Get-UpdateStatus {
    $latestTag = Get-LatestReleaseTag
    $latestVersion = ConvertFrom-VersionTag -Tag $latestTag
    $currentVersion = ConvertFrom-VersionTag -Tag $AppVersion
    $cmp = Compare-VersionText -A $latestVersion -B $currentVersion

    [pscustomobject]@{
        CurrentVersion = $currentVersion
        LatestVersion = $latestVersion
        LatestTag = $latestTag
        UpdateAvailable = ($cmp -gt 0)
    }
}


function Format-UpdateStatusText {
    param([pscustomobject]$Status)

    if ($Status.UpdateAvailable) {
        return "Update available: v$($Status.LatestVersion). Current version: v$($Status.CurrentVersion)."
    }

    return 'You are already up to date.'
}

function Invoke-CheckUpdateCommand {
    try {
        $status = Get-UpdateStatus
        return (Format-UpdateStatusText -Status $status)
    } catch {
        throw "Update check failed. Check your internet connection, GitHub access, and the release tag format. Details: $($_.Exception.Message)"
    }
}

function Invoke-UpdateCommand {
    try {
        $status = Get-UpdateStatus
        if (-not $status.UpdateAvailable) {
            return 'You are already up to date.'
        }

        $started = Start-UpdateProcessFromUi
        if (-not $started) {
            throw 'Failed to start update process as administrator.'
        }

        return "Update available: v$($status.LatestVersion). Current version: v$($status.CurrentVersion). Update started."
    } catch {
        throw "Update failed. Details: $($_.Exception.Message)"
    }
}

function Invoke-RepairCommand {
    $started = Start-RepairProcessFromUi
    if (-not $started) {
        throw 'Failed to start repair process as administrator.'
    }

    return 'Repair started.'
}

function Set-MtuConfigFromCommandLine {
    param(
        [bool]$HasIPv4,
        [string]$IPv4Value,
        [bool]$HasIPv6,
        [string]$IPv6Value,
        [bool]$HasInterval,
        [int]$IntervalSeconds,
        [bool]$HasEnableState,
        [bool]$EnableState
    )

    $cfg = Get-Config

    $mtu4 = [int]$cfg.desired_mtu_ipv4
    $mtu6 = [int]$cfg.desired_mtu_ipv6
    $interval = [int]$cfg.check_interval_seconds
    $enabled = [bool]$cfg.enabled

    if ($HasIPv4) {
        if (-not [int]::TryParse($IPv4Value, [ref]$mtu4)) {
            throw [System.ArgumentException]::new('IPv4 MTU must be a number.')
        }
    }

    if ($HasIPv6) {
        if (-not [int]::TryParse($IPv6Value, [ref]$mtu6)) {
            throw [System.ArgumentException]::new('IPv6 MTU must be a number.')
        }
    }

    if ($HasInterval) {
        if ($IntervalSeconds -lt 10 -or $IntervalSeconds -gt 86400) {
            throw [System.ArgumentException]::new('Interval must be between 10 and 86400 seconds.')
        }
        $interval = [int]$IntervalSeconds
    }

    if ($HasEnableState) { $enabled = [bool]$EnableState }

    Save-Config -DesiredMtuIPv4 $mtu4 -DesiredMtuIPv6 $mtu6 -Enabled $enabled -InterfaceMatch ([string]$cfg.interface_match) -CheckIntervalSeconds $interval | Out-Null
    Request-PendingApply

    $serviceBefore = Get-ServiceStatusText
    $serviceStarted = $false

    if ($enabled -and $serviceBefore -ne 'Running' -and $serviceBefore -ne 'Not installed') {
        $serviceStarted = Start-BackgroundServiceSafe
    }

    $serviceAfter = Get-ServiceStatusText

    @(
        'Config updated.',
        "Enabled: $enabled",
        "Desired MTU IPv4: $mtu4",
        "Desired MTU IPv6: $mtu6",
        "Check Interval (s): $interval",
        "Interface Match: $($cfg.interface_match)",
        'Apply queued: True',
        "Service Status: $serviceAfter",
        "Service Start Attempted: $serviceStarted"
    ) -join [Environment]::NewLine
}

function Start-AppDirectoryCleanup {
    param([string]$PathToRemove)

    if ([string]::IsNullOrWhiteSpace($PathToRemove)) { return $false }
    if (-not (Test-Path -LiteralPath $PathToRemove)) { return $true }

    $pwsh = Get-PowerShellExePath
    if (-not (Test-Path -LiteralPath $pwsh)) { return $false }

    $tempDir = [System.IO.Path]::GetTempPath()
    $cleanupScript = Join-Path $tempDir ("TailscaleMTU-Purge-" + [guid]::NewGuid().ToString('N') + ".ps1")

    $scriptContent = @"
param([string]`$TargetPath)
Set-Location -LiteralPath '$($tempDir.Replace("'", "''"))'
Start-Sleep -Seconds 3

for (`$i = 0; `$i -lt 120; `$i++) {
    try {
        if (-not (Test-Path -LiteralPath `$TargetPath)) { exit 0 }
        Remove-Item -LiteralPath `$TargetPath -Recurse -Force -ErrorAction Stop
        if (-not (Test-Path -LiteralPath `$TargetPath)) { exit 0 }
    } catch {
    }
    Start-Sleep -Seconds 1
}

exit 1
"@

    try {
        Set-Content -LiteralPath $cleanupScript -Value $scriptContent -Encoding UTF8 -Force

        Start-Process -FilePath $pwsh `
            -ArgumentList @(
                '-NoProfile'
                '-ExecutionPolicy', 'Bypass'
                '-WindowStyle', 'Hidden'
                '-File', "`"$cleanupScript`""
                '-TargetPath', "`"$PathToRemove`""
            ) `
            -WorkingDirectory $tempDir `
            -WindowStyle Hidden | Out-Null

        return $true
    } catch {
        return $false
    }
}

function Start-UninstallProcessFromUi {
    try {
        $pwsh = Get-PowerShellExePath
        if (-not (Test-Path -LiteralPath $pwsh)) { return $false }

        $sourceScript = $null
        if ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath)) {
            $sourceScript = $ScriptPath
        } elseif (Test-Path -LiteralPath $ScriptDest) {
            $sourceScript = $ScriptDest
        } else {
            try {
                $sourceScript = Get-ResolvedScriptPath
            } catch {
                $sourceScript = $null
            }
        }

        if ([string]::IsNullOrWhiteSpace($sourceScript)) { return $false }

        $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) ("Tailscale-MTU-Uninstall-" + [guid]::NewGuid().ToString('N') + ".ps1")
        Copy-Item -LiteralPath $sourceScript -Destination $tempScript -Force

        $uninstallArgs = @(
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-WindowStyle', 'Hidden'
            '-File', "`"$tempScript`""
            '-Uninstall'
            '-Purge'
            '-Force'
        )

        Start-Process -FilePath $pwsh -ArgumentList ($uninstallArgs -join ' ') -Verb RunAs -WindowStyle Hidden | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Install-TailscaleMtu {
    $installSwitches = @('-Install')
    if ($NoOpenUi) { $installSwitches += '-NoOpenUi' }
    Invoke-AdminRelaunchIfNeeded -ModeSwitches $installSwitches

    Initialize-AppDirectory
    Copy-ScriptToAppDirectory | Out-Null
    Initialize-ConfigStore | Out-Null
    Initialize-StateStore | Out-Null
    Install-NssmBinary | Out-Null
    Install-AppIcon | Out-Null
    New-UiLauncherVbs | Out-Null
    Set-AppPermissions
    Install-BackgroundService
    
    $shortcut = New-StartMenuShortcut
    $status = Get-ServiceStatusText

    $uiOpened = $false
    if (-not $NoOpenUi) {
        $uiOpened = Start-MtuGuiFromShortcut
        if (-not $uiOpened) {
            $uiOpened = Start-MtuGuiProcess
        }
    }

    @(
        'Installed successfully.'
        "Service: $ServiceDisplayName ($status)"
        "Service Internal Name: $ServiceName"
        "Script: $ScriptDest"
        "UI Launcher: $UiLauncherVbsPath"
        "NSSM: $NssmPath"
        "Config: $ConfigPath"
        "State: $StatePath"
        "Shortcut: $shortcut"
        if ($NoOpenUi) { 'UI: not opened because -NoOpenUi was used.' } elseif ($uiOpened) { 'UI: opened via Start Menu shortcut.' } else { 'UI: failed to open automatically. Open Start Menu > Tailscale MTU' }
    ) -join [Environment]::NewLine
}

function Show-WindowByTitle {
    param([string]$Title)

    try {
        if (-not ('TailscaleMtu.WindowTools' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace TailscaleMtu {
    public static class WindowTools {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        public static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        public static extern bool BringWindowToTop(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
    }
}
"@ -ErrorAction Stop | Out-Null
        }

        $handle = [TailscaleMtu.WindowTools]::FindWindow($null, $Title)
        if ($handle -eq [IntPtr]::Zero) { return $false }

        if ([TailscaleMtu.WindowTools]::IsIconic($handle)) {
            [void][TailscaleMtu.WindowTools]::ShowWindowAsync($handle, 9)
        } else {
            [void][TailscaleMtu.WindowTools]::ShowWindowAsync($handle, 5)
        }

        [void][TailscaleMtu.WindowTools]::BringWindowToTop($handle)
        [void][TailscaleMtu.WindowTools]::SetForegroundWindow($handle)
        return $true
    } catch {
        return $false
    }
}

function Show-UninstallConfirmationDialog {
    param(
        [bool]$PurgeRequested,
        [string]$ScopeText
    )

    $dialogMutex = $null
    $dialogMutexCreated = $false

    try {
        try {
            $dialogMutex = [System.Threading.Mutex]::new($true, $UninstallDialogMutexName, [ref]$dialogMutexCreated)
            if (-not $dialogMutexCreated) {
                [void](Show-WindowByTitle -Title $AppDisplayName)
                return $false
            }
        } catch {
            try { if ($dialogMutex) { $dialogMutex.Dispose() } } catch { }
            $dialogMutex = $null
        }

        Enable-DpiAwareness
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        Add-Type -AssemblyName Microsoft.VisualBasic | Out-Null
        Set-ProcessAppUserModelId
        try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }

        $prompt = if ($PurgeRequested) {
            "Type 'uninstall' to confirm full removal.`n`n$ScopeText"
        } else {
            "Type 'uninstall' to confirm uninstall.`n`n$ScopeText"
        }

        $answer = [Microsoft.VisualBasic.Interaction]::InputBox(
            $prompt,
            $AppDisplayName,
            ''
        )

        if ($null -eq $answer) { return $false }

        $normalizedAnswer = $answer.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalizedAnswer)) { return $false }

        if ($normalizedAnswer -ne 'uninstall') {
            [System.Windows.Forms.MessageBox]::Show(
                'Confirmation text did not match. Uninstall was not started.',
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return $false
        }

        return $true
    } catch {
        return $null
    } finally {
        try {
            if ($dialogMutex) {
                if ($dialogMutexCreated) { $dialogMutex.ReleaseMutex() | Out-Null }
                $dialogMutex.Dispose()
            }
        } catch {
        }
    }
}

function Confirm-UninstallTailscaleMtu {
    param([bool]$PurgeRequested)

    $scopeText = if ($PurgeRequested) {
        "This will remove the Windows service, shortcut, launcher, config, state, logs, and app files in $AppDir."
    } else {
        "This will remove the Windows service, shortcut, and launcher. Config, state, and logs in $AppDir will be kept."
    }

    $dialogResult = Show-UninstallConfirmationDialog -PurgeRequested $PurgeRequested -ScopeText $scopeText
    if ($null -ne $dialogResult) { return [bool]$dialogResult }

    if (-not [string]::IsNullOrWhiteSpace([string]$ResultPath)) {
        Write-Output 'Uninstall was not started because graphical confirmation could not be opened.'
        return $false
    }

    Write-Output 'Tailscale MTU uninstall confirmation'
    Write-Output $scopeText
    Write-Output "Type 'uninstall' to continue."

    try {
        $answer = Read-Host 'Confirmation'
    } catch {
        Write-Output 'Uninstall was not started because confirmation could not be read. Use -Force for unattended uninstall.'
        return $false
    }

    if ($null -eq $answer) { return $false }
    return ($answer.Trim().ToLowerInvariant() -eq 'uninstall')
}

function Uninstall-TailscaleMtu {
    $alreadyConfirmed = $false

    if (-not $Force) {
        $confirmed = Confirm-UninstallTailscaleMtu -PurgeRequested ($Purge.IsPresent)
        if (-not $confirmed) {
            Write-UninstallResult -Status 'cancelled' -Message 'Uninstall cancelled by user.' -ExitCode 0
            return 'Uninstall cancelled.'
        }
        $alreadyConfirmed = $true
    }

    $uninstallSwitches = @('-Uninstall')
    if ($Purge) { $uninstallSwitches += '-Purge' }
    if ($Force -or $alreadyConfirmed) { $uninstallSwitches += '-Force' }
    if (-not [string]::IsNullOrWhiteSpace([string]$ResultPath)) { $uninstallSwitches += @('-ResultPath', ('"' + [string]$ResultPath + '"')) }
    Invoke-AdminRelaunchIfNeeded -ModeSwitches $uninstallSwitches

    Uninstall-BackgroundService
    Remove-StartMenuShortcut

    try {
        if (Test-Path -LiteralPath $UiLauncherVbsPath) {
            Remove-Item -LiteralPath $UiLauncherVbsPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
    }

    $purgeRequested = $Purge.IsPresent
    $cleanupStarted = $false

    if ($purgeRequested) {
        Start-Sleep -Seconds 2
        $cleanupStarted = Start-AppDirectoryCleanup -PathToRemove $AppDir
    }

    if ($purgeRequested) {
        if ($cleanupStarted) {
            $message = "Removed service and shortcut. Purge was started in background for $AppDir. Wait a few seconds and refresh the folder."
        } else {
            $message = "Removed service and shortcut. Failed to start automatic file cleanup for $AppDir."
        }
    } else {
        $message = "Removed service and shortcut. Files in $AppDir were kept."
    }

    Write-UninstallResult -Status 'uninstalled' -Message $message -ExitCode 0
    return $message
}

function Enable-DpiAwareness {
    try {
        if (-not ('TailscaleMtu.NativeMethods' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace TailscaleMtu {
    public static class NativeMethods {
        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();

        [DllImport("shcore.dll")]
        public static extern int SetProcessDpiAwareness(int value);
    }
}
"@ -ErrorAction Stop | Out-Null
        }

        try {
            [void][TailscaleMtu.NativeMethods]::SetProcessDpiAwareness(1)
        } catch {
            try {
                [void][TailscaleMtu.NativeMethods]::SetProcessDPIAware()
            } catch {
            }
        }
    } catch {
    }
}


function Show-ExistingMtuGuiWindow {
    try {
        if (-not ('TailscaleMtu.User32' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace TailscaleMtu {
    public static class User32 {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        public static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        public static extern bool BringWindowToTop(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
    }
}
"@ -ErrorAction Stop | Out-Null
        }

        $title = "$AppDisplayName v$AppVersion"
        $handle = [TailscaleMtu.User32]::FindWindow($null, $title)

        if ($handle -eq [IntPtr]::Zero) {
            try {
                $proc = Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.MainWindowTitle -eq $title -and $_.MainWindowHandle -ne [IntPtr]::Zero } |
                    Select-Object -First 1
                if ($null -ne $proc) { $handle = $proc.MainWindowHandle }
            } catch {
            }
        }

        if ($handle -eq [IntPtr]::Zero) { return $false }

        if ([TailscaleMtu.User32]::IsIconic($handle)) {
            [void][TailscaleMtu.User32]::ShowWindowAsync($handle, 9)
        } else {
            [void][TailscaleMtu.User32]::ShowWindowAsync($handle, 5)
        }

        [void][TailscaleMtu.User32]::BringWindowToTop($handle)
        [void][TailscaleMtu.User32]::SetForegroundWindow($handle)
        return $true
    } catch {
        return $false
    }
}

function Show-MtuGui {
    try {
        Enable-DpiAwareness
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Set-ProcessAppUserModelId
        [System.Windows.Forms.Application]::EnableVisualStyles()
        [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)
    } catch {
        Write-Host 'Failed to load WinForms. Use Windows PowerShell (powershell.exe).' -ForegroundColor Red
        return
    }

    $uiMutex = $null
    $uiMutexCreated = $false
    try {
        $uiMutex = [System.Threading.Mutex]::new($true, $UiMutexName, [ref]$uiMutexCreated)
        if (-not $uiMutexCreated) {
            [void](Show-ExistingMtuGuiWindow)
            try { $uiMutex.Dispose() } catch {}
            return
        }
    } catch {
        try { if ($uiMutex) { $uiMutex.Dispose() } } catch {}
        throw
    }

    Initialize-AppDirectory
    Initialize-ConfigStore | Out-Null
    Get-StateSafe | Out-Null
    try { Install-AppIcon | Out-Null } catch {}

    $colorBg = [System.Drawing.Color]::FromArgb(246, 248, 252)
    $colorPanel = [System.Drawing.Color]::White
    $colorHeader = [System.Drawing.Color]::FromArgb(22, 78, 170)
    $colorHeaderText = [System.Drawing.Color]::White
    $colorMuted = [System.Drawing.Color]::FromArgb(93, 108, 137)
    $colorOk = [System.Drawing.Color]::FromArgb(220, 252, 231)
    $colorOkText = [System.Drawing.Color]::FromArgb(22, 101, 52)
    $colorWarn = [System.Drawing.Color]::FromArgb(254, 249, 195)
    $colorWarnText = [System.Drawing.Color]::FromArgb(133, 77, 14)
    $colorError = [System.Drawing.Color]::FromArgb(254, 226, 226)
    $colorErrorText = [System.Drawing.Color]::FromArgb(153, 27, 27)

    $fontLabel = New-Object System.Drawing.Font('Segoe UI', 9)
    $fontBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $fontTitle = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
    $fontHeaderSmall = New-Object System.Drawing.Font('Segoe UI', 9)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$AppDisplayName v$AppVersion"
    $form.StartPosition = 'Manual'
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::None
    $form.ClientSize = New-Object System.Drawing.Size(820, 830)
    $form.MinimumSize = New-Object System.Drawing.Size(820, 830)
    $form.MaximizeBox = $false
    $form.FormBorderStyle = 'FixedDialog'
    $form.BackColor = $colorBg
    $form.ShowIcon = $true
    $form.ShowInTaskbar = $true

    $appIcon = $null
    $headerIconObject = $null
    $headerBitmap = $null
    try {
        if (Test-Path -LiteralPath $IconPath) {
            try {
                $appIcon = New-Object System.Drawing.Icon($IconPath, 256, 256)
            } catch {
                $appIcon = New-Object System.Drawing.Icon($IconPath)
            }

            $form.Icon = $appIcon

            try {
                $headerIconObject = New-Object System.Drawing.Icon($IconPath, 256, 256)
            } catch {
                try {
                    $headerIconObject = New-Object System.Drawing.Icon($IconPath, 128, 128)
                } catch {
                    $headerIconObject = New-Object System.Drawing.Icon($IconPath, 64, 64)
                }
            }

            $headerBitmap = $headerIconObject.ToBitmap()
        }
    } catch {
        $appIcon = $null
        $headerIconObject = $null
        $headerBitmap = $null
    }

    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $headerPanel.Size = New-Object System.Drawing.Size(820, 78)
    $headerPanel.BackColor = $colorHeader
    $form.Controls.Add($headerPanel)

    if ($headerBitmap) {
        $headerIcon = New-Object System.Windows.Forms.PictureBox
        $headerIcon.Location = New-Object System.Drawing.Point(14, 9)
        $headerIcon.Size = New-Object System.Drawing.Size(60, 60)
        $headerIcon.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
        $headerIcon.Image = $headerBitmap
        $headerPanel.Controls.Add($headerIcon)
    }

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Location = New-Object System.Drawing.Point(90, 12)
    $lblTitle.Size = New-Object System.Drawing.Size(500, 28)
    $lblTitle.Font = $fontTitle
    $lblTitle.ForeColor = $colorHeaderText
    $lblTitle.Text = "$AppDisplayName v$AppVersion"
    $headerPanel.Controls.Add($lblTitle)

    $lblIntro = New-Object System.Windows.Forms.Label
    $lblIntro.Location = New-Object System.Drawing.Point(90, 42)
    $lblIntro.Size = New-Object System.Drawing.Size(710, 24)
    $lblIntro.Font = $fontHeaderSmall
    $lblIntro.ForeColor = [System.Drawing.Color]::FromArgb(231, 238, 255)
    $lblIntro.Text = 'Edit the config here. The Windows service keeps the MTU persistent in the background.'
    $headerPanel.Controls.Add($lblIntro)

    $lblBanner = New-Object System.Windows.Forms.Label
    $lblBanner.Location = New-Object System.Drawing.Point(16, 90)
    $lblBanner.Size = New-Object System.Drawing.Size(788, 30)
    $lblBanner.Font = $fontBold
    $lblBanner.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $lblBanner.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $lblBanner.BackColor = $colorWarn
    $lblBanner.ForeColor = $colorWarnText
    $lblBanner.Text = ' Loading status...'
    $form.Controls.Add($lblBanner)

    $grpCurrent = New-Object System.Windows.Forms.GroupBox
    $grpCurrent.Location = New-Object System.Drawing.Point(16, 130)
    $grpCurrent.Size = New-Object System.Drawing.Size(788, 148)
    $grpCurrent.Text = 'Current Status'
    $grpCurrent.Font = $fontBold
    $grpCurrent.BackColor = $colorPanel
    $form.Controls.Add($grpCurrent)

    $grpSettings = New-Object System.Windows.Forms.GroupBox
    $grpSettings.Location = New-Object System.Drawing.Point(16, 286)
    $grpSettings.Size = New-Object System.Drawing.Size(788, 210)
    $grpSettings.Text = 'Settings'
    $grpSettings.Font = $fontBold
    $grpSettings.BackColor = $colorPanel
    $form.Controls.Add($grpSettings)

    $grpActivity = New-Object System.Windows.Forms.GroupBox
    $grpActivity.Location = New-Object System.Drawing.Point(16, 504)
    $grpActivity.Size = New-Object System.Drawing.Size(788, 166)
    $grpActivity.Text = 'Service Activity'
    $grpActivity.Font = $fontBold
    $grpActivity.BackColor = $colorPanel
    $form.Controls.Add($grpActivity)

    function Add-InfoRow {
        param(
            [System.Windows.Forms.Control]$Parent,
            [string]$Title,
            [int]$Top,
            [int]$LeftLabel = 14,
            [int]$LeftValue = 220,
            [int]$ValueWidth = 580
        )

        $lblT = New-Object System.Windows.Forms.Label
        $lblT.Location = New-Object System.Drawing.Point($LeftLabel, $Top)
        $lblT.Size = New-Object System.Drawing.Size(($LeftValue - $LeftLabel - 10), 20)
        $lblT.Font = $fontBold
        $lblT.Text = $Title
        $Parent.Controls.Add($lblT)

        $lblV = New-Object System.Windows.Forms.Label
        $lblV.Location = New-Object System.Drawing.Point($LeftValue, $Top)
        $lblV.Size = New-Object System.Drawing.Size($ValueWidth, 20)
        $lblV.Font = $fontLabel
        $lblV.Text = '-'
        $lblV.AutoEllipsis = $true
        $Parent.Controls.Add($lblV)

        return $lblV
    }

    $lblService = Add-InfoRow -Parent $grpCurrent -Title 'Service Status:' -Top 24 -LeftValue 220 -ValueWidth 546
    $lblIface = Add-InfoRow -Parent $grpCurrent -Title 'Detected Interface:' -Top 50 -LeftValue 220 -ValueWidth 546
    $lblCur4 = Add-InfoRow -Parent $grpCurrent -Title 'Current MTU (IPv4):' -Top 76 -LeftValue 220 -ValueWidth 546
    $lblCur6 = Add-InfoRow -Parent $grpCurrent -Title 'Current MTU (IPv6):' -Top 102 -LeftValue 220 -ValueWidth 546

    $lblDesired4Title = New-Object System.Windows.Forms.Label
    $lblDesired4Title.Location = New-Object System.Drawing.Point(14, 28)
    $lblDesired4Title.Size = New-Object System.Drawing.Size(190, 20)
    $lblDesired4Title.Font = $fontBold
    $lblDesired4Title.Text = 'Desired MTU (IPv4):'
    $grpSettings.Controls.Add($lblDesired4Title)

    $txtDesired4 = New-Object System.Windows.Forms.TextBox
    $txtDesired4.Location = New-Object System.Drawing.Point(220, 25)
    $txtDesired4.Size = New-Object System.Drawing.Size(150, 24)
    $txtDesired4.Font = $fontLabel
    $txtDesired4.HideSelection = $true
    $txtDesired4.TabIndex = 10
    $grpSettings.Controls.Add($txtDesired4)

    $lblDesired4Hint = New-Object System.Windows.Forms.Label
    $lblDesired4Hint.Location = New-Object System.Drawing.Point(390, 28)
    $lblDesired4Hint.Size = New-Object System.Drawing.Size(380, 20)
    $lblDesired4Hint.Font = $fontLabel
    $lblDesired4Hint.ForeColor = $colorMuted
    $lblDesired4Hint.Text = "Range: $MinMtuIPv4 to $MaxMtu"
    $grpSettings.Controls.Add($lblDesired4Hint)

    $lblDesired6Title = New-Object System.Windows.Forms.Label
    $lblDesired6Title.Location = New-Object System.Drawing.Point(14, 61)
    $lblDesired6Title.Size = New-Object System.Drawing.Size(190, 20)
    $lblDesired6Title.Font = $fontBold
    $lblDesired6Title.Text = 'Desired MTU (IPv6):'
    $grpSettings.Controls.Add($lblDesired6Title)

    $txtDesired6 = New-Object System.Windows.Forms.TextBox
    $txtDesired6.Location = New-Object System.Drawing.Point(220, 58)
    $txtDesired6.Size = New-Object System.Drawing.Size(150, 24)
    $txtDesired6.Font = $fontLabel
    $txtDesired6.HideSelection = $true
    $txtDesired6.TabIndex = 11
    $grpSettings.Controls.Add($txtDesired6)

    $lblDesired6Hint = New-Object System.Windows.Forms.Label
    $lblDesired6Hint.Location = New-Object System.Drawing.Point(390, 61)
    $lblDesired6Hint.Size = New-Object System.Drawing.Size(380, 20)
    $lblDesired6Hint.Font = $fontLabel
    $lblDesired6Hint.ForeColor = $colorMuted
    $lblDesired6Hint.Text = "Range: $MinMtuIPv6 to $MaxMtu"
    $grpSettings.Controls.Add($lblDesired6Hint)

    $chkEnabled = New-Object System.Windows.Forms.CheckBox
    $chkEnabled.Location = New-Object System.Drawing.Point(220, 91)
    $chkEnabled.Size = New-Object System.Drawing.Size(220, 24)
    $chkEnabled.Font = $fontLabel
    $chkEnabled.Text = 'Enable MTU Enforcer'
    $chkEnabled.Checked = $true
    $chkEnabled.TabIndex = 12
    $grpSettings.Controls.Add($chkEnabled)

    $lblIntervalTitle = New-Object System.Windows.Forms.Label
    $lblIntervalTitle.Location = New-Object System.Drawing.Point(14, 124)
    $lblIntervalTitle.Size = New-Object System.Drawing.Size(190, 20)
    $lblIntervalTitle.Font = $fontBold
    $lblIntervalTitle.Text = 'Check Interval (sec):'
    $grpSettings.Controls.Add($lblIntervalTitle)

    $txtInterval = New-Object System.Windows.Forms.TextBox
    $txtInterval.Location = New-Object System.Drawing.Point(220, 121)
    $txtInterval.Size = New-Object System.Drawing.Size(150, 24)
    $txtInterval.Font = $fontLabel
    $txtInterval.HideSelection = $true
    $txtInterval.TabIndex = 13
    $grpSettings.Controls.Add($txtInterval)

    $lblIntervalHint = New-Object System.Windows.Forms.Label
    $lblIntervalHint.Location = New-Object System.Drawing.Point(390, 124)
    $lblIntervalHint.Size = New-Object System.Drawing.Size(380, 20)
    $lblIntervalHint.Font = $fontLabel
    $lblIntervalHint.ForeColor = $colorMuted
    $lblIntervalHint.Text = 'Default: 60 seconds.'
    $grpSettings.Controls.Add($lblIntervalHint)

    $lblMatchTitle = New-Object System.Windows.Forms.Label
    $lblMatchTitle.Location = New-Object System.Drawing.Point(14, 157)
    $lblMatchTitle.Size = New-Object System.Drawing.Size(190, 20)
    $lblMatchTitle.Font = $fontBold
    $lblMatchTitle.Text = 'Interface Match Text:'
    $grpSettings.Controls.Add($lblMatchTitle)

    $txtMatch = New-Object System.Windows.Forms.TextBox
    $txtMatch.Location = New-Object System.Drawing.Point(220, 154)
    $txtMatch.Size = New-Object System.Drawing.Size(300, 24)
    $txtMatch.Font = $fontLabel
    $txtMatch.HideSelection = $true
    $txtMatch.TabIndex = 14
    $grpSettings.Controls.Add($txtMatch)

    $lblTip = New-Object System.Windows.Forms.Label
    $lblTip.Location = New-Object System.Drawing.Point(14, 182)
    $lblTip.Size = New-Object System.Drawing.Size(756, 20)
    $lblTip.Font = $fontLabel
    $lblTip.ForeColor = $colorMuted
    $lblTip.Text = 'Use "Save and Apply" after changing values. Local edits stay in the form until you save or refresh.'
    $grpSettings.Controls.Add($lblTip)

    $lblSaved4 = Add-InfoRow -Parent $grpActivity -Title 'Saved Desired MTU (IPv4):' -Top 24 -LeftValue 220 -ValueWidth 546
    $lblSaved6 = Add-InfoRow -Parent $grpActivity -Title 'Saved Desired MTU (IPv6):' -Top 50 -LeftValue 220 -ValueWidth 546
    $lblLast = Add-InfoRow -Parent $grpActivity -Title 'Last Result:' -Top 76 -LeftValue 220 -ValueWidth 546
    $lblLastApply = Add-InfoRow -Parent $grpActivity -Title 'Last Apply (UTC):' -Top 102 -LeftValue 220 -ValueWidth 546
    $lblHeartbeat = Add-InfoRow -Parent $grpActivity -Title 'Service Heartbeat:' -Top 128 -LeftValue 220 -ValueWidth 546

    $lblError = New-Object System.Windows.Forms.Label
    $lblError.Location = New-Object System.Drawing.Point(16, 676)
    $lblError.Size = New-Object System.Drawing.Size(788, 36)
    $lblError.Font = $fontLabel
    $lblError.ForeColor = $colorMuted
    $lblError.AutoEllipsis = $false
    $lblError.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
    $lblError.Text = 'Last Error: -'
    $lblError.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $form.Controls.Add($lblError)

    $lblPaths = New-Object System.Windows.Forms.Label
    $lblPaths.Location = New-Object System.Drawing.Point(16, 716)
    $lblPaths.Size = New-Object System.Drawing.Size(490, 44)
    $lblPaths.Font = $fontLabel
    $lblPaths.ForeColor = $colorMuted
    $lblPaths.AutoEllipsis = $false
    $lblPaths.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
    $lblPaths.Text = ''
    $lblPaths.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $form.Controls.Add($lblPaths)

    $lblCopyright = New-Object System.Windows.Forms.Label
    $lblCopyright.Location = New-Object System.Drawing.Point(540, 738)
    $lblCopyright.Size = New-Object System.Drawing.Size(264, 22)
    $lblCopyright.Font = $fontLabel
    $lblCopyright.ForeColor = $colorMuted
    $lblCopyright.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $lblCopyright.Text = ('Copyright ' + [char]0x00A9 + ' 2026 Luiz Bizzio')
    $lblCopyright.Anchor = [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $form.Controls.Add($lblCopyright)

    $bottomPanel = New-Object System.Windows.Forms.Panel
    $bottomPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $bottomPanel.Height = 58
    $bottomPanel.BackColor = [System.Drawing.Color]::FromArgb(241, 244, 250)
    $bottomPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $form.Controls.Add($bottomPanel)

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Location = New-Object System.Drawing.Point(12, 13)
    $btnRefresh.Size = New-Object System.Drawing.Size(88, 30)
    $btnRefresh.Text = 'Refresh'
    $btnRefresh.TabIndex = 0
    $bottomPanel.Controls.Add($btnRefresh)

    $btnDefault = New-Object System.Windows.Forms.Button
    $btnDefault.Location = New-Object System.Drawing.Point(106, 13)
    $btnDefault.Size = New-Object System.Drawing.Size(105, 30)
    $btnDefault.Text = 'Set Default'
    $btnDefault.TabIndex = 1
    $bottomPanel.Controls.Add($btnDefault)

    $btnSaveApply = New-Object System.Windows.Forms.Button
    $btnSaveApply.Location = New-Object System.Drawing.Point(217, 13)
    $btnSaveApply.Size = New-Object System.Drawing.Size(130, 30)
    $btnSaveApply.Text = 'Save and Apply'
    $btnSaveApply.TabIndex = 2
    $bottomPanel.Controls.Add($btnSaveApply)

    $btnCheckUpdate = New-Object System.Windows.Forms.Button
    $btnCheckUpdate.Location = New-Object System.Drawing.Point(410, 13)
    $btnCheckUpdate.Size = New-Object System.Drawing.Size(112, 30)
    $btnCheckUpdate.Text = 'Check Update'
    $btnCheckUpdate.TabIndex = 3
    $bottomPanel.Controls.Add($btnCheckUpdate)

    $btnUpdate = New-Object System.Windows.Forms.Button
    $btnUpdate.Location = New-Object System.Drawing.Point(530, 13)
    $btnUpdate.Size = New-Object System.Drawing.Size(78, 30)
    $btnUpdate.Text = 'Update'
    $btnUpdate.TabIndex = 4
    $btnUpdate.Enabled = $false
    $bottomPanel.Controls.Add($btnUpdate)

    $btnRepair = New-Object System.Windows.Forms.Button
    $btnRepair.Location = New-Object System.Drawing.Point(616, 13)
    $btnRepair.Size = New-Object System.Drawing.Size(84, 30)
    $btnRepair.Text = 'Repair'
    $btnRepair.TabIndex = 5
    $bottomPanel.Controls.Add($btnRepair)

    $btnUninstall = New-Object System.Windows.Forms.Button
    $btnUninstall.Location = New-Object System.Drawing.Point(708, 13)
    $btnUninstall.Size = New-Object System.Drawing.Size(100, 30)
    $btnUninstall.Text = 'Uninstall'
    $btnUninstall.TabIndex = 6
    $bottomPanel.Controls.Add($btnUninstall)

    $bottomButtons = @($btnRefresh, $btnDefault, $btnSaveApply, $btnCheckUpdate, $btnUpdate, $btnRepair, $btnUninstall)

    foreach ($b in $bottomButtons) {
        $b.UseVisualStyleBackColor = $false
        $b.BackColor = [System.Drawing.Color]::White
        $b.ForeColor = [System.Drawing.Color]::Black
        $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
        $b.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    }

    $toolTip = New-Object System.Windows.Forms.ToolTip
    $toolTip.AutoPopDelay = 12000
    $toolTip.InitialDelay = 500
    $toolTip.ReshowDelay = 100
    $toolTip.ShowAlways = $true

    $toolTip.SetToolTip($txtDesired4, 'MTU value applied to the Tailscale IPv4 interface. 1280 is the safe default for Tailscale. Use a higher value only if your path supports it.')
    $toolTip.SetToolTip($txtDesired6, 'MTU value applied to the Tailscale IPv6 interface. IPv6 requires at least 1280.')
    $toolTip.SetToolTip($txtInterval, 'How often the background service verifies and reapplies the MTU. Default is 60 seconds.')
    $toolTip.SetToolTip($txtMatch, 'Text used to find the Tailscale adapter by name or description. Keep Tailscale unless your adapter uses a custom name.')
    $toolTip.SetToolTip($btnCheckUpdate, 'Checks the latest GitHub Release and reports whether a newer version exists. It does not install anything.')
    $toolTip.SetToolTip($btnUpdate, 'Checks the latest GitHub Release and installs it if a newer version exists.')
    $toolTip.SetToolTip($btnRepair, 'Repairs the local service and shortcut using the installed version. Keeps config, state, and logs.')

    $uiState = [hashtable]::Synchronized(@{
        Dirty = $false
        LoadingInputs = $false
        UpdateAvailable = $false
        LatestVersion = $null
        LatestTag = $null
    })

    $txtDesired4.Add_TextChanged({
        if (-not $uiState.LoadingInputs) {
            $uiState.Dirty = $true
        }
    })

    $txtDesired6.Add_TextChanged({
        if (-not $uiState.LoadingInputs) {
            $uiState.Dirty = $true
        }
    })

    $txtInterval.Add_TextChanged({
        if (-not $uiState.LoadingInputs) {
            $uiState.Dirty = $true
        }
    })

    $txtMatch.Add_TextChanged({
        if (-not $uiState.LoadingInputs) {
            $uiState.Dirty = $true
        }
    })

    $chkEnabled.Add_CheckedChanged({
        if (-not $uiState.LoadingInputs) {
            $uiState.Dirty = $true
        }
    })

    function Set-BannerState {
        param(
            [string]$ServiceStatus,
            [string]$LastResult,
            [bool]$Enabled,
            [string]$LastErrorValue,
            [string]$HeartbeatStatus,
            [bool]$PendingApply
        )

        $message = ''
        $bg = $colorWarn
        $fg = $colorWarnText

        if ($ServiceStatus -ne 'Running') {
            $bg = $colorWarn
            $fg = $colorWarnText
            $message = ' Service is not running. Save is allowed, but apply may not be processed until the service starts.'
        } elseif ($LastResult -eq 'error') {
            $bg = $colorError
            $fg = $colorErrorText
            $message = ' Last apply error. Check "Last Error" below for details.'
        } elseif ($HeartbeatStatus -in @('stale', 'missing', 'invalid')) {
            $bg = $colorWarn
            $fg = $colorWarnText
            if ($PendingApply) {
                $message = ' Apply is pending, but the service heartbeat is stale. Click Repair to restart/reinstall the service.'
            } else {
                $message = ' Service is running, but the heartbeat is stale. Click Repair if values stop applying.'
            }
        } elseif ($PendingApply) {
            $bg = $colorWarn
            $fg = $colorWarnText
            $message = ' Apply is pending. The service should process it shortly.'
        } elseif (-not $Enabled) {
            $bg = $colorWarn
            $fg = $colorWarnText
            $message = ' MTU enforcer is disabled in config.'
        } elseif ($LastResult -eq 'interface_not_found') {
            $bg = $colorWarn
            $fg = $colorWarnText
            $message = ' Tailscale interface not found right now.'
        } elseif ($uiState.Dirty) {
            $bg = $colorWarn
            $fg = $colorWarnText
            $message = ' You have unsaved changes. Click Save and Apply to keep them.'
        } else {
            $bg = $colorOk
            $fg = $colorOkText
            $message = ' Service running. Saved values are synchronized.'
        }

        $lblBanner.BackColor = $bg
        $lblBanner.ForeColor = $fg
        $lblBanner.Text = $message
    }

    $refreshUi = {
        param([bool]$ForceInputs = $false)

        try {
            $s = Get-StatusObject

            if ($s.service_start_mode -and $s.service_dependencies) {
                $lblService.Text = "$($s.service_status) | $($s.service_start_mode) | depends on $($s.service_dependencies)"
            } elseif ($s.service_start_mode) {
                $lblService.Text = "$($s.service_status) | $($s.service_start_mode)"
            } else {
                $lblService.Text = [string]$s.service_status
            }
            $lblIface.Text = if ($s.detected_interface) { [string]$s.detected_interface } else { 'Not found' }
            $lblCur4.Text = if ($null -ne $s.current_mtu_ipv4) { [string]$s.current_mtu_ipv4 } else { '-' }
            $lblCur6.Text = if ($null -ne $s.current_mtu_ipv6) { [string]$s.current_mtu_ipv6 } else { '-' }

            if ($ForceInputs -or (-not $uiState.Dirty)) {
                $uiState.LoadingInputs = $true
                try {
                    $txtDesired4.Text = [string]$s.desired_mtu_ipv4
                    $txtDesired6.Text = [string]$s.desired_mtu_ipv6
                    $txtInterval.Text = [string]$s.check_interval_seconds
                    $txtMatch.Text = [string]$s.interface_match
                    $chkEnabled.Checked = [bool]$s.enabled
                } finally {
                    $uiState.LoadingInputs = $false
                }

                if ($ForceInputs) {
                    $uiState.Dirty = $false
                }
            }

            $lblSaved4.Text = [string]$s.desired_mtu_ipv4
            $lblSaved6.Text = [string]$s.desired_mtu_ipv6
            $lblLast.Text = if ($s.pending_apply) { "$($s.last_result) | pending apply" } else { [string]$s.last_result }
            $lblLastApply.Text = if ($s.last_apply_utc) { [string]$s.last_apply_utc } else { '-' }
            $lblHeartbeat.Text = if ($s.service_heartbeat_utc) { "$($s.service_heartbeat_utc) ($($s.service_heartbeat_status), $($s.service_heartbeat_age_seconds)s ago)" } else { [string]$s.service_heartbeat_status }

            $errorText = if ($s.last_error) { [string]$s.last_error } else { '-' }
            $lblError.Text = "Last Error: $errorText"
            if ($s.last_error) {
                $lblError.ForeColor = $colorErrorText
            } else {
                $lblError.ForeColor = $colorMuted
            }

            $lblPaths.Text = "Config: $ConfigPath`nState: $StatePath"
            try { $lblCopyright.BringToFront() } catch {}

            Set-BannerState -ServiceStatus ([string]$s.service_status) -LastResult ([string]$s.last_result) -Enabled ([bool]$s.enabled) -LastErrorValue ([string]$s.last_error) -HeartbeatStatus ([string]$s.service_heartbeat_status) -PendingApply ([bool]$s.pending_apply)
        } catch {
            $lblBanner.BackColor = $colorError
            $lblBanner.ForeColor = $colorErrorText
            $lblBanner.Text = " Failed to load status: $($_.Exception.Message)"
            $lblError.Text = "Last Error: $($_.Exception.Message)"
            $lblError.ForeColor = $colorErrorText
        }
    }

    $saveAndApplyFromUi = {
        try {
            $rawMtu4 = $txtDesired4.Text.Trim()
            $rawMtu6 = $txtDesired6.Text.Trim()
            $rawInterval = $txtInterval.Text.Trim()
            $rawMatch = $txtMatch.Text.Trim()

            $mtu4 = 0
            if (-not [int]::TryParse($rawMtu4, [ref]$mtu4)) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Enter a valid numeric IPv4 MTU.',
                    $AppDisplayName,
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return $false
            }

            $mtu6 = 0
            if (-not [int]::TryParse($rawMtu6, [ref]$mtu6)) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Enter a valid numeric IPv6 MTU.',
                    $AppDisplayName,
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return $false
            }

            $interval = 0
            if (-not [int]::TryParse($rawInterval, [ref]$interval)) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Enter a valid numeric check interval in seconds.',
                    $AppDisplayName,
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return $false
            }

            if ($mtu4 -lt $MinMtuIPv4 -or $mtu4 -gt $MaxMtu) {
                [System.Windows.Forms.MessageBox]::Show(
                    "IPv4 MTU must be between $MinMtuIPv4 and $MaxMtu.",
                    $AppDisplayName,
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return $false
            }

            if ($mtu6 -lt $MinMtuIPv6 -or $mtu6 -gt $MaxMtu) {
                [System.Windows.Forms.MessageBox]::Show(
                    "IPv6 MTU must be between $MinMtuIPv6 and $MaxMtu.",
                    $AppDisplayName,
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return $false
            }

            if ($interval -lt 10 -or $interval -gt 86400) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Check interval must be between 10 and 86400 seconds.',
                    $AppDisplayName,
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return $false
            }

            Save-Config -DesiredMtuIPv4 $mtu4 -DesiredMtuIPv6 $mtu6 -Enabled $chkEnabled.Checked -InterfaceMatch $rawMatch -CheckIntervalSeconds $interval | Out-Null
            $uiState.Dirty = $false
            Request-PendingApply

            $serviceBeforeSave = Get-ServiceStatusText
            $serviceStartAttempted = $false
            $serviceStarted = $false

            if ($chkEnabled.Checked -and $serviceBeforeSave -ne 'Running' -and $serviceBeforeSave -ne 'Not installed') {
                $serviceStartAttempted = $true
                $serviceStarted = Start-BackgroundServiceSafe

                for ($i = 0; $i -lt 10; $i++) {
                    if ((Get-ServiceStatusText) -eq 'Running') { break }
                    Start-Sleep -Milliseconds 500
                }
            } else {
                Start-Sleep -Milliseconds 800
            }

            & $refreshUi $true
            $statusAfterSave = Get-StatusObject
            if (([string]$statusAfterSave.service_status) -ne 'Running') {
                $lblBanner.BackColor = $colorWarn
                $lblBanner.ForeColor = $colorWarnText

                if ($serviceBeforeSave -eq 'Not installed') {
                    $lblBanner.Text = ' Config saved, but the service is not installed. Run Repair or Install as administrator.'
                } elseif ($serviceStartAttempted -and -not $serviceStarted) {
                    $lblBanner.Text = ' Config saved, but the service could not be started automatically. Run Repair as administrator.'
                } elseif (-not $chkEnabled.Checked) {
                    $lblBanner.Text = ' Config saved. MTU enforcer is disabled, so the service was not started.'
                } else {
                    $lblBanner.Text = ' Config saved and apply was queued, but the service is not running. Run Repair as administrator.'
                }
            } elseif ([string]$statusAfterSave.service_heartbeat_status -in @('stale', 'missing', 'invalid')) {
                $lblBanner.BackColor = $colorWarn
                $lblBanner.ForeColor = $colorWarnText
                $lblBanner.Text = ' Config saved, but the service heartbeat is stale. Click Repair to restart/reinstall the service so it can apply the MTU.'
            } elseif ([bool]$statusAfterSave.pending_apply) {
                $lblBanner.BackColor = $colorWarn
                $lblBanner.ForeColor = $colorWarnText
                $lblBanner.Text = ' Config saved. Apply is pending and should be processed shortly.'
            } else {
                $lblBanner.BackColor = $colorOk
                $lblBanner.ForeColor = $colorOkText
                $lblBanner.Text = ' Config saved and applied successfully.'
            }

            return $true
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to save/apply: $($_.Exception.Message)`nIf this is the first run, execute -Install as administrator.",
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            return $false
        }
    }

    $runRepairFromUi = {
        $result = [System.Windows.Forms.MessageBox]::Show(
            'Repair will reinstall the local Windows service and shortcut using the currently installed version. Config, state, and logs will be kept. Continue?',
            $AppDisplayName,
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $started = Start-RepairProcessFromUi -ReopenUi
        if (-not $started) {
            [System.Windows.Forms.MessageBox]::Show(
                'Failed to start repair process as administrator.',
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            return
        }

        $lblBanner.BackColor = $colorWarn
        $lblBanner.ForeColor = $colorWarnText
        $lblBanner.Text = ' Repair started. This window will close and reopen when repair finishes.'
        $form.Close()
    }
    $runCheckUpdateFromUi = {
        $oldCheckText = $btnCheckUpdate.Text
        $btnUpdate.Enabled = $false
        $btnCheckUpdate.Text = 'Checking'
        [void]$btnCheckUpdate.Focus()

        try {
            $status = Get-UpdateStatus
            $uiState.UpdateAvailable = [bool]$status.UpdateAvailable
            $uiState.LatestVersion = [string]$status.LatestVersion
            $uiState.LatestTag = [string]$status.LatestTag

            if ($status.UpdateAvailable) {
                $lblBanner.BackColor = $colorWarn
                $lblBanner.ForeColor = $colorWarnText
                $lblBanner.Text = " Update available: v$($status.LatestVersion). Current version: v$($status.CurrentVersion)."
                $btnUpdate.Enabled = $true
            } else {
                $lblBanner.BackColor = $colorOk
                $lblBanner.ForeColor = $colorOkText
                $lblBanner.Text = ' You are already up to date.'
                $btnUpdate.Enabled = $false
            }
        } catch {
            $uiState.UpdateAvailable = $false
            $btnUpdate.Enabled = $false
            $lblBanner.BackColor = $colorError
            $lblBanner.ForeColor = $colorErrorText
            $lblBanner.Text = ' Update check failed.'
            [System.Windows.Forms.MessageBox]::Show(
                "Update check failed. Check your internet connection, GitHub access, and the release tag format.`n`nDetails: $($_.Exception.Message)",
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        } finally {
            if (-not $form.IsDisposed) {
                $btnCheckUpdate.Text = $oldCheckText
                [void]$btnCheckUpdate.Focus()
            }
        }
    }

    $runUpdateFromUi = {
        if (-not $uiState.UpdateAvailable) {
            $lblBanner.BackColor = $colorWarn
            $lblBanner.ForeColor = $colorWarnText
            $lblBanner.Text = ' Click Check Update first. Update is enabled only when a newer release exists.'
            return
        }

        $result = [System.Windows.Forms.MessageBox]::Show(
            "Update available: v$($uiState.LatestVersion). Current version: v$AppVersion. Update now?",
            $AppDisplayName,
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $oldText = $btnUpdate.Text
        $btnUpdate.Enabled = $false
        $btnCheckUpdate.Enabled = $false
        $btnUpdate.Text = 'Updating'

        try {
            $started = Start-UpdateProcessFromUi -ReopenUi
            if (-not $started) {
                throw 'Failed to start update process as administrator.'
            }

            $form.Close()
        } catch {
            $btnUpdate.Text = $oldText
            $btnCheckUpdate.Enabled = $true
            $btnUpdate.Enabled = [bool]$uiState.UpdateAvailable
            [System.Windows.Forms.MessageBox]::Show(
                "Update failed.`n`nDetails: $($_.Exception.Message)",
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    }

    $runUninstallFromUi = {
        try {
            Add-Type -AssemblyName Microsoft.VisualBasic | Out-Null
        } catch {
        }

        $confirmText = ''
        try {
            $confirmText = [Microsoft.VisualBasic.Interaction]::InputBox(
                "Type 'uninstall' to confirm full removal.`nThis will remove the Windows service, shortcut, and all files in:`n$AppDir",
                $AppDisplayName,
                ''
            )
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                'Could not open confirmation prompt.',
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            return
        }

        if ($null -eq $confirmText) { return }

        $normalizedConfirmText = $confirmText.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalizedConfirmText)) { return }

        if ($normalizedConfirmText -ne 'uninstall') {
            [System.Windows.Forms.MessageBox]::Show(
                'Confirmation text did not match. Uninstall was not started.',
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        $started = Start-UninstallProcessFromUi
        if (-not $started) {
            [System.Windows.Forms.MessageBox]::Show(
                'Failed to start uninstall process as administrator.',
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            return
        }

        $form.Close()
    }

    $centerForm = {
        try {
            $screen = [System.Windows.Forms.Screen]::FromControl($form)
            if (-not $screen) { $screen = [System.Windows.Forms.Screen]::PrimaryScreen }
            $area = $screen.WorkingArea
            $x = [int]($area.Left + (($area.Width - $form.Width) / 2))
            $y = [int]($area.Top + (($area.Height - $form.Height) / 2))
            if ($x -lt $area.Left) { $x = $area.Left }
            if ($y -lt $area.Top) { $y = $area.Top }
            $form.Location = New-Object System.Drawing.Point($x, $y)
        } catch {
        }
    }

    $form.Add_Load({ & $centerForm })

    $uiTimer = New-Object System.Windows.Forms.Timer
    $uiTimer.Interval = 5000
    $uiTimer.Add_Tick({
        try {
            if (-not $form.IsDisposed -and $form.Visible) {
                & $refreshUi
            }
        } catch {
        }
    })

    $btnRefresh.Add_Click({
        if (-not $uiState.Dirty) {
            & $refreshUi $true
            return
        }
    
        $result = [System.Windows.Forms.MessageBox]::Show(
            'Refresh will discard unsaved changes and reload values from disk. Continue?',
            $AppDisplayName,
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
    
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            & $refreshUi $true
        }
    })

    $btnDefault.Add_Click({
        $txtDesired4.Text = '1280'
        $txtDesired6.Text = '1280'
        $txtInterval.Text = [string]$DefaultCheckIntervalSeconds
        $txtMatch.Text = 'Tailscale'
        $chkEnabled.Checked = $true
    })

    $btnSaveApply.Add_Click({ [void](& $saveAndApplyFromUi) })
    $btnCheckUpdate.Add_Click({ & $runCheckUpdateFromUi })
    $btnUpdate.Add_Click({ & $runUpdateFromUi })
    $btnRepair.Add_Click({ & $runRepairFromUi })
    $btnUninstall.Add_Click({ & $runUninstallFromUi })

    $form.Add_Shown({
        & $centerForm
        & $refreshUi $true
        try { $lblCopyright.BringToFront() } catch {}
        $uiTimer.Start()
        [void]$btnRefresh.Focus()
    })

    $form.Add_FormClosing({
        try { $uiTimer.Stop() } catch {}
        try { if ($toolTip) { $toolTip.Dispose() } } catch {}
        try { if ($headerBitmap) { $headerBitmap.Dispose() } } catch {}
        try { if ($headerIconObject) { $headerIconObject.Dispose() } } catch {}
        try { if ($appIcon) { $appIcon.Dispose() } } catch {}
        try { if ($uiMutexCreated -and $uiMutex) { [void]$uiMutex.ReleaseMutex() } } catch {}
        try { if ($uiMutex) { $uiMutex.Dispose() } } catch {}
        $uiMutexCreated = $false
        $uiMutex = $null
    })

    [void]$form.ShowDialog()
}

try {
    if ($Install) {
        Write-Output (Install-TailscaleMtu)
        exit 0
    }

    if ($Uninstall) {
        Write-Output (Uninstall-TailscaleMtu)
        exit 0
    }

    if ($CheckUpdate) {
        $status = Get-UpdateStatus
        Write-Output (Format-UpdateStatusText -Status $status)
        if ($status.UpdateAvailable) { exit 0 } else { exit 3 }
    }

    if ($Update) {
        $status = Get-UpdateStatus
        if (-not $status.UpdateAvailable) {
            Write-Output 'You are already up to date.'
            exit 3
        }

        Write-Output (Invoke-UpdateCommand)
        exit 0
    }

    if ($Repair) {
        Write-Output (Invoke-RepairCommand)
        exit 0
    }

    if ($RunLoop) {
        Invoke-RunLoop
        exit 0
    }

    if ($Apply) {
        $r = Invoke-Apply
        if ($r.Ok) { exit 0 } else { Write-Error $r.Error; exit 1 }
    }

    if ($Status) {
        Write-Output (Write-StatusJson)
        exit 0
    }

    if ($Enable -and $Disable) {
        throw [System.ArgumentException]::new('Use either -Enable or -Disable, not both.')
    }

    $hasMtuCommand = $PSBoundParameters.ContainsKey('IPv4') -or $PSBoundParameters.ContainsKey('IPv6') -or $PSBoundParameters.ContainsKey('Interval') -or $Enable -or $Disable
    if ($hasMtuCommand) {
        $hasEnableState = ($Enable -or $Disable)
        $enableState = $true
        if ($Disable) { $enableState = $false }
        Write-Output (Set-MtuConfigFromCommandLine -HasIPv4 ($PSBoundParameters.ContainsKey('IPv4')) -IPv4Value $IPv4 -HasIPv6 ($PSBoundParameters.ContainsKey('IPv6')) -IPv6Value $IPv6 -HasInterval ($PSBoundParameters.ContainsKey('Interval')) -IntervalSeconds $Interval -HasEnableState $hasEnableState -EnableState $enableState)
        exit 0
    }

    if ($UI -or (-not $Install -and -not $Uninstall -and -not $RunLoop -and -not $Apply -and -not $Status -and -not $CheckUpdate -and -not $Update -and -not $Repair -and -not $NoOpenUi)) {
        Show-MtuGui
        exit 0
    }

    exit 0
} catch {
    $msg = $_.Exception.Message
    Write-Error $msg
    if ($_.Exception -is [System.ArgumentException]) {
        if ($Uninstall) { Write-UninstallResult -Status 'failed' -Message $msg -ExitCode 2 }
        exit 2
    }
    if ($msg -match 'administrator|elevat|RunAs') {
        if ($Uninstall) { Write-UninstallResult -Status 'failed' -Message $msg -ExitCode 4 }
        exit 4
    }
    if ($Uninstall) { Write-UninstallResult -Status 'failed' -Message $msg -ExitCode 1 }
    exit 1
}
