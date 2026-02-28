[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$UI,
    [switch]$RunLoop,
    [switch]$Apply,
    [switch]$Status
)

$AppDisplayName = 'Tailscale MTU'
$ServiceName = 'TailscaleMTU'
$ServiceDisplayName = 'Tailscale MTU'
$ServiceDescription = 'Keeps Tailscale MTU persistent based on user config.'
$AppDir = Join-Path $env:ProgramData 'TailscaleMTU'
$LogDir = Join-Path $AppDir 'logs'
$ScriptDest = Join-Path $AppDir 'Tailscale-MTU.ps1'
$ConfigPath = Join-Path $AppDir 'config.json'
$StatePath = Join-Path $AppDir 'state.json'
$StateMutexName = 'Global\TailscaleMTU_StateLock'
$NssmPath = Join-Path $AppDir 'nssm.exe'
$UiLauncherVbsPath = Join-Path $AppDir 'Open-Tailscale-MTU.vbs'
$NssmDownloadUrl = 'https://raw.githubusercontent.com/luizbizzio/tailscale-mtu/main/windows/nssm.exe'
$SetupScriptUrl = 'https://raw.githubusercontent.com/luizbizzio/tailscale-mtu/main/windows/windows-setup.ps1'
$IconPath = Join-Path $AppDir 'tailscale-mtu.ico'
$IconDownloadUrl = 'https://raw.githubusercontent.com/luizbizzio/tailscale-mtu/main/windows/tailscale-mtu.ico'
$MinMtuIPv4 = 576
$MinMtuIPv6 = 1280
$MaxMtu = 9000
$LoopTickMilliseconds = 250
$HeartbeatWriteSeconds = 5
$ScriptPath = $PSCommandPath
if (-not $ScriptPath) { $ScriptPath = $MyInvocation.MyCommand.Path }

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

function ConvertTo-UtcDateTimeSafe {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        return [DateTime]::Parse($Value).ToUniversalTime()
    } catch {
        return $null
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

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    for ($i = 0; $i -lt 5; $i++) {
        try {
            $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
            return $raw | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 40
        }
    }
    return $null
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Data
    )

    $json = $Data | ConvertTo-Json -Depth 20

    if (Test-Path -LiteralPath $Path) {
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
        return
    }

    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8 -Force
}

function Invoke-WithStateLock {
    param(
        [scriptblock]$ScriptBlock,
        [int]$TimeoutMilliseconds = 5000
    )

    $mutex = $null
    $hasLock = $false

    try {
        $mutex = [System.Threading.Mutex]::new($false, $StateMutexName)

        try {
            $hasLock = $mutex.WaitOne($TimeoutMilliseconds)
        } catch [System.Threading.AbandonedMutexException] {
            $hasLock = $true
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
        check_interval_seconds = 5
    }
}

function Get-DefaultState {
    [ordered]@{
        pending_apply = $false
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
    $interval = 5

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

    try { $interval = [int]$cfg.check_interval_seconds } catch { $interval = 5 }

    $desired4 = [int](Get-ClampedInt -Value $desired4 -Min $MinMtuIPv4 -Max $MaxMtu)
    $desired6 = [int](Get-ClampedInt -Value $desired6 -Min $MinMtuIPv6 -Max $MaxMtu)
    $interval = [int](Get-ClampedInt -Value $interval -Min 1 -Max 86400)

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

    if ($CheckIntervalSeconds -lt 1) { $CheckIntervalSeconds = 1 }
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

        foreach ($k in $Patch.Keys) {
            if ($st.PSObject.Properties[$k]) {
                $st.$k = $Patch[$k]
            } else {
                Add-Member -InputObject $st -MemberType NoteProperty -Name $k -Value $Patch[$k]
            }
        }

        Write-JsonFile -Path $StatePath -Data $st
        return $st
    })
}

function Request-PendingApply {
    Update-State @{ pending_apply = $true } | Out-Null
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
    Copy-Item -LiteralPath $resolvedScriptPath -Destination $ScriptDest -Force
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
    $needDownload = $true
    if (Test-ExeLooksValid -Path $NssmPath) { $needDownload = $false }
    if (-not $needDownload) { return $NssmPath }

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

function Install-BackgroundService {
    $nssm = Install-NssmBinary
    $pwsh = Get-PowerShellExePath
    if (-not (Test-Path -LiteralPath $pwsh)) { throw "PowerShell executable not found at $pwsh" }

    $outLog = Join-Path $LogDir 'service.out.log'
    $errLog = Join-Path $LogDir 'service.err.log'
    $psArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptDest`" -RunLoop"

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        & $nssm stop $ServiceName *> $null
        Start-Sleep -Milliseconds 300
        & $nssm remove $ServiceName confirm *> $null
        if (-not (Wait-ServiceGone -Name $ServiceName -TimeoutSeconds 20)) {
            & sc.exe delete $ServiceName *> $null
            if (-not (Wait-ServiceGone -Name $ServiceName -TimeoutSeconds 20)) {
                throw 'Service removal is still pending. Close Services MMC or reboot, then run Install/Reinstall again.'
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

    & $nssm set $ServiceName ObjectName LocalSystem *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set LocalSystem.' }

    & $nssm set $ServiceName AppDirectory $AppDir *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set AppDirectory.' }

    & $nssm set $ServiceName AppStdout $outLog *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set AppStdout.' }

    & $nssm set $ServiceName AppStderr $errLog *> $null
    if ($LASTEXITCODE -ne 0) { throw 'NSSM failed to set AppStderr.' }

    & $nssm set $ServiceName AppRotateFiles 1 *> $null
    & $nssm set $ServiceName AppRotateOnline 1 *> $null
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
            pending_apply = $false
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

        $patch = @{
            pending_apply = $false
            last_result = if ($changed) { 'applied' } else { 'already_ok' }
            last_error = $null
            last_check_utc = $now
            desired_mtu_ipv4 = $cfg.desired_mtu_ipv4
            desired_mtu_ipv6 = $cfg.desired_mtu_ipv6
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

function Invoke-RunLoop {
    $nextHeartbeat = [DateTime]::UtcNow
    while ($true) {
        try {
            $nowDt = [DateTime]::UtcNow
            if ($nowDt -ge $nextHeartbeat) {
                Update-State @{ service_heartbeat_utc = $nowDt.ToString('o') } | Out-Null
                $nextHeartbeat = $nowDt.AddSeconds($HeartbeatWriteSeconds)
            }
        } catch {
        }

        try {
            Invoke-Apply | Out-Null
        } catch {
            try {
                Update-State @{
                    last_result = 'error'
                    last_error = $_.Exception.Message
                } | Out-Null
            } catch {
            }
        }

        Start-Sleep -Milliseconds $LoopTickMilliseconds
    }
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

    [pscustomobject]@{
        service_name = $ServiceName
        service_status = $svcStatus
        app_dir = $AppDir
        script_path = $ScriptDest
        config_path = $ConfigPath
        state_path = $StatePath
        nssm_path = $NssmPath
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
    }
}

function Write-StatusText {
    $s = Get-StatusObject
    @(
        "Service Name: $($s.service_name)"
        "Service Status: $($s.service_status)"
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
    ) -join [Environment]::NewLine
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

function Start-ReinstallProcessFromUi {
    try {
        $pwsh = Get-PowerShellExePath
        if (-not (Test-Path -LiteralPath $pwsh)) { return $false }

        $tmpScript = Join-Path ([System.IO.Path]::GetTempPath()) ("Tailscale-MTU-Reinstall-" + [guid]::NewGuid().ToString('N') + ".ps1")
        Invoke-WebRequest -Uri $SetupScriptUrl -OutFile $tmpScript -UseBasicParsing -ErrorAction Stop

        $reinstallArgs = @(
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-WindowStyle', 'Hidden'
            '-File', "`"$tmpScript`""
            '-Install'
        )

        Start-Process -FilePath $pwsh -ArgumentList ($reinstallArgs -join ' ') -Verb RunAs -WindowStyle Hidden | Out-Null
        return $true
    } catch {
        return $false
    }
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
        )

        Start-Process -FilePath $pwsh -ArgumentList ($uninstallArgs -join ' ') -Verb RunAs -WindowStyle Hidden | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Install-TailscaleMtu {
    Invoke-AdminRelaunchIfNeeded -ModeSwitches @('-Install')

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

    $uiOpened = Start-MtuGuiFromShortcut
    if (-not $uiOpened) {
        $uiOpened = Start-MtuGuiProcess
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
        if ($uiOpened) { 'UI: opened via Start Menu shortcut.' } else { 'UI: failed to open automatically. Open Start Menu > Tailscale MTU' }
    ) -join [Environment]::NewLine
}

function Uninstall-TailscaleMtu {
    $uninstallSwitches = @('-Uninstall')
    if ($Purge) { $uninstallSwitches += '-Purge' }
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
            "Removed service and shortcut. Purge was started in background for $AppDir. Wait a few seconds and refresh the folder."
        } else {
            "Removed service and shortcut. Failed to start automatic file cleanup for $AppDir."
        }
    } else {
        "Removed service and shortcut. Files in $AppDir were kept."
    }
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
            [void][TailscaleMtu.NativeMethods]::SetProcessDpiAwareness(2)
        } catch {
            try {
                [void][TailscaleMtu.NativeMethods]::SetProcessDPIAware()
            } catch {
            }
        }
    } catch {
    }
}

function Show-MtuGui {
    try {
        Enable-DpiAwareness
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        [System.Windows.Forms.Application]::EnableVisualStyles()
    } catch {
        Write-Host 'Failed to load WinForms. Use Windows PowerShell (powershell.exe).' -ForegroundColor Red
        return
    }

    Initialize-AppDirectory
    Initialize-ConfigStore | Out-Null
    Get-StateSafe | Out-Null

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
    $fontTitle = New-Object System.Drawing.Font('Segoe UI Semibold', 13, [System.Drawing.FontStyle]::Bold)
    $fontHeaderSmall = New-Object System.Drawing.Font('Segoe UI', 9)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $AppDisplayName
    $form.StartPosition = 'CenterScreen'
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
    $form.ClientSize = New-Object System.Drawing.Size(860, 830)
    $form.MinimumSize = New-Object System.Drawing.Size(860, 830)
    $form.MaximizeBox = $false
    $form.FormBorderStyle = 'FixedDialog'
    $form.BackColor = $colorBg

    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $headerPanel.Size = New-Object System.Drawing.Size(860, 78)
    $headerPanel.BackColor = $colorHeader
    $form.Controls.Add($headerPanel)

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Location = New-Object System.Drawing.Point(16, 12)
    $lblTitle.Size = New-Object System.Drawing.Size(360, 28)
    $lblTitle.Font = $fontTitle
    $lblTitle.ForeColor = $colorHeaderText
    $lblTitle.Text = 'Tailscale MTU'
    $headerPanel.Controls.Add($lblTitle)

    $lblIntro = New-Object System.Windows.Forms.Label
    $lblIntro.Location = New-Object System.Drawing.Point(16, 42)
    $lblIntro.Size = New-Object System.Drawing.Size(820, 24)
    $lblIntro.Font = $fontHeaderSmall
    $lblIntro.ForeColor = [System.Drawing.Color]::FromArgb(231, 238, 255)
    $lblIntro.Text = 'Edit the config here. The Windows service keeps the MTU persistent in the background.'
    $headerPanel.Controls.Add($lblIntro)

    $lblBanner = New-Object System.Windows.Forms.Label
    $lblBanner.Location = New-Object System.Drawing.Point(16, 90)
    $lblBanner.Size = New-Object System.Drawing.Size(828, 30)
    $lblBanner.Font = $fontBold
    $lblBanner.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $lblBanner.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $lblBanner.BackColor = $colorWarn
    $lblBanner.ForeColor = $colorWarnText
    $lblBanner.Text = ' Loading status...'
    $form.Controls.Add($lblBanner)

    $grpCurrent = New-Object System.Windows.Forms.GroupBox
    $grpCurrent.Location = New-Object System.Drawing.Point(16, 130)
    $grpCurrent.Size = New-Object System.Drawing.Size(828, 148)
    $grpCurrent.Text = 'Current Status'
    $grpCurrent.Font = $fontBold
    $grpCurrent.BackColor = $colorPanel
    $form.Controls.Add($grpCurrent)

    $grpSettings = New-Object System.Windows.Forms.GroupBox
    $grpSettings.Location = New-Object System.Drawing.Point(16, 286)
    $grpSettings.Size = New-Object System.Drawing.Size(828, 210)
    $grpSettings.Text = 'Settings'
    $grpSettings.Font = $fontBold
    $grpSettings.BackColor = $colorPanel
    $form.Controls.Add($grpSettings)

    $grpActivity = New-Object System.Windows.Forms.GroupBox
    $grpActivity.Location = New-Object System.Drawing.Point(16, 504)
    $grpActivity.Size = New-Object System.Drawing.Size(828, 166)
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

    $lblService = Add-InfoRow -Parent $grpCurrent -Title 'Service Status:' -Top 24 -LeftValue 220 -ValueWidth 586
    $lblIface = Add-InfoRow -Parent $grpCurrent -Title 'Detected Interface:' -Top 50 -LeftValue 220 -ValueWidth 586
    $lblCur4 = Add-InfoRow -Parent $grpCurrent -Title 'Current MTU (IPv4):' -Top 76 -LeftValue 220 -ValueWidth 586
    $lblCur6 = Add-InfoRow -Parent $grpCurrent -Title 'Current MTU (IPv6):' -Top 102 -LeftValue 220 -ValueWidth 586

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
    $lblDesired4Hint.Size = New-Object System.Drawing.Size(420, 20)
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
    $lblDesired6Hint.Size = New-Object System.Drawing.Size(420, 20)
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
    $lblIntervalHint.Size = New-Object System.Drawing.Size(420, 20)
    $lblIntervalHint.Font = $fontLabel
    $lblIntervalHint.ForeColor = $colorMuted
    $lblIntervalHint.Text = 'Minimum 1 second. Lower values mean more frequent checks.'
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
    $lblTip.Size = New-Object System.Drawing.Size(796, 20)
    $lblTip.Font = $fontLabel
    $lblTip.ForeColor = $colorMuted
    $lblTip.Text = 'Use "Save and Apply" after changing values. Local edits stay in the form until you save or refresh.'
    $grpSettings.Controls.Add($lblTip)

    $lblSaved4 = Add-InfoRow -Parent $grpActivity -Title 'Saved Desired MTU (IPv4):' -Top 24 -LeftValue 220 -ValueWidth 586
    $lblSaved6 = Add-InfoRow -Parent $grpActivity -Title 'Saved Desired MTU (IPv6):' -Top 50 -LeftValue 220 -ValueWidth 586
    $lblLast = Add-InfoRow -Parent $grpActivity -Title 'Last Result:' -Top 76 -LeftValue 220 -ValueWidth 586
    $lblLastApply = Add-InfoRow -Parent $grpActivity -Title 'Last Apply (UTC):' -Top 102 -LeftValue 220 -ValueWidth 586
    $lblHeartbeat = Add-InfoRow -Parent $grpActivity -Title 'Service Heartbeat:' -Top 128 -LeftValue 220 -ValueWidth 586

    $lblError = New-Object System.Windows.Forms.Label
    $lblError.Location = New-Object System.Drawing.Point(16, 676)
    $lblError.Size = New-Object System.Drawing.Size(828, 36)
    $lblError.Font = $fontLabel
    $lblError.ForeColor = $colorMuted
    $lblError.AutoEllipsis = $false
    $lblError.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
    $lblError.Text = 'Last Error: -'
    $lblError.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $form.Controls.Add($lblError)

    $lblPaths = New-Object System.Windows.Forms.Label
    $lblPaths.Location = New-Object System.Drawing.Point(16, 716)
    $lblPaths.Size = New-Object System.Drawing.Size(828, 44)
    $lblPaths.Font = $fontLabel
    $lblPaths.ForeColor = $colorMuted
    $lblPaths.AutoEllipsis = $false
    $lblPaths.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
    $lblPaths.Text = ''
    $lblPaths.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $form.Controls.Add($lblPaths)

    $bottomPanel = New-Object System.Windows.Forms.Panel
    $bottomPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $bottomPanel.Height = 58
    $bottomPanel.BackColor = [System.Drawing.Color]::FromArgb(241, 244, 250)
    $bottomPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $form.Controls.Add($bottomPanel)

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Location = New-Object System.Drawing.Point(12, 13)
    $btnRefresh.Size = New-Object System.Drawing.Size(100, 30)
    $btnRefresh.Text = 'Refresh'
    $btnRefresh.TabIndex = 0
    $bottomPanel.Controls.Add($btnRefresh)

    $btnDefault = New-Object System.Windows.Forms.Button
    $btnDefault.Location = New-Object System.Drawing.Point(118, 13)
    $btnDefault.Size = New-Object System.Drawing.Size(142, 30)
    $btnDefault.Text = 'Set Default (1280)'
    $btnDefault.TabIndex = 1
    $bottomPanel.Controls.Add($btnDefault)

    $btnSaveApply = New-Object System.Windows.Forms.Button
    $btnSaveApply.Location = New-Object System.Drawing.Point(266, 13)
    $btnSaveApply.Size = New-Object System.Drawing.Size(150, 30)
    $btnSaveApply.Text = 'Save and Apply'
    $btnSaveApply.TabIndex = 2
    $bottomPanel.Controls.Add($btnSaveApply)

    $btnReinstall = New-Object System.Windows.Forms.Button
    $btnReinstall.Location = New-Object System.Drawing.Point(422, 13)
    $btnReinstall.Size = New-Object System.Drawing.Size(100, 30)
    $btnReinstall.Text = 'Reinstall'
    $btnReinstall.TabIndex = 3
    $bottomPanel.Controls.Add($btnReinstall)

    $btnUninstall = New-Object System.Windows.Forms.Button
    $btnUninstall.Location = New-Object System.Drawing.Point(528, 13)
    $btnUninstall.Size = New-Object System.Drawing.Size(100, 30)
    $btnUninstall.Text = 'Uninstall'
    $btnUninstall.TabIndex = 4
    $bottomPanel.Controls.Add($btnUninstall)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Location = New-Object System.Drawing.Point(734, 13)
    $btnClose.Size = New-Object System.Drawing.Size(100, 30)
    $btnClose.Text = 'Close'
    $btnClose.TabIndex = 5
    $bottomPanel.Controls.Add($btnClose)

    $bottomButtons = @($btnRefresh, $btnDefault, $btnSaveApply, $btnReinstall, $btnUninstall, $btnClose)

    foreach ($b in $bottomButtons) {
        $b.UseVisualStyleBackColor = $false
        $b.BackColor = [System.Drawing.Color]::White
        $b.ForeColor = [System.Drawing.Color]::Black
        $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    }

    $uiState = [hashtable]::Synchronized(@{
        Dirty = $false
        LoadingInputs = $false
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
            [string]$LastErrorValue
        )

        $message = ''
        $bg = $colorWarn
        $fg = $colorWarnText

        if ($ServiceStatus -ne 'Running') {
            $bg = $colorWarn
            $fg = $colorWarnText
            $message = ' Service is not running. Save is allowed, but apply may not be processed until the service starts.'
        } elseif (-not $Enabled) {
            $bg = $colorWarn
            $fg = $colorWarnText
            $message = ' MTU enforcer is disabled in config.'
        } elseif ($LastResult -eq 'error') {
            $bg = $colorError
            $fg = $colorErrorText
            $message = ' Last apply error. Check "Last Error" below for details.'
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

            $lblService.Text = [string]$s.service_status
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
            $lblHeartbeat.Text = if ($s.service_heartbeat_utc) { [string]$s.service_heartbeat_utc } else { '-' }

            $errorText = if ($s.last_error) { [string]$s.last_error } else { '-' }
            $lblError.Text = "Last Error: $errorText"
            if ($s.last_error) {
                $lblError.ForeColor = $colorErrorText
            } else {
                $lblError.ForeColor = $colorMuted
            }

            $lblPaths.Text = "Config: $ConfigPath`nState: $StatePath"

            Set-BannerState -ServiceStatus ([string]$s.service_status) -LastResult ([string]$s.last_result) -Enabled ([bool]$s.enabled) -LastErrorValue ([string]$s.last_error)
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

            if ($interval -lt 1) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Check interval must be at least 1 second.',
                    $AppDisplayName,
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return $false
            }

            Save-Config -DesiredMtuIPv4 $mtu4 -DesiredMtuIPv6 $mtu6 -Enabled $chkEnabled.Checked -InterfaceMatch $rawMatch -CheckIntervalSeconds $interval | Out-Null
            $uiState.Dirty = $false
            Request-PendingApply

            if ((Get-ServiceStatusText) -ne 'Running') {
                Start-BackgroundServiceSafe | Out-Null
            }

            Start-Sleep -Milliseconds 800
            & $refreshUi $true

            $msg = if ((Get-ServiceStatusText) -eq 'Running') {
                'Config saved. Apply was requested and the service is processing it.'
            } else {
                'Config saved and apply was queued, but the service is not running. Start the service or run Reinstall as administrator.'
            }

            [System.Windows.Forms.MessageBox]::Show(
                $msg,
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null

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

    $runReinstallFromUi = {
        $result = [System.Windows.Forms.MessageBox]::Show(
            'Reinstall will download the latest windows-setup.ps1 from GitHub and reinstall the Windows service. Continue?',
            $AppDisplayName,
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $started = Start-ReinstallProcessFromUi
        if (-not $started) {
            [System.Windows.Forms.MessageBox]::Show(
                'Failed to start reinstall process as administrator.',
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            return
        }

        [System.Windows.Forms.MessageBox]::Show(
            'Reinstall started. This window will close.',
            $AppDisplayName,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

        $form.Close()
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
        if ($confirmText.Trim().ToLowerInvariant() -ne 'uninstall') {
            [System.Windows.Forms.MessageBox]::Show(
                'Uninstall canceled. Confirmation text did not match.',
                $AppDisplayName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
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

        [System.Windows.Forms.MessageBox]::Show(
            'Uninstall started. This window will close.',
            $AppDisplayName,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

        $form.Close()
    }

    $uiTimer = New-Object System.Windows.Forms.Timer
    $uiTimer.Interval = 2000
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
    })

    $btnSaveApply.Add_Click({ [void](& $saveAndApplyFromUi) })
    $btnReinstall.Add_Click({ & $runReinstallFromUi })
    $btnUninstall.Add_Click({ & $runUninstallFromUi })
    $btnClose.Add_Click({ $form.Close() })

    $form.Add_Shown({
        & $refreshUi $true
        $uiTimer.Start()
        [void]$btnRefresh.Focus()
    })

    $form.Add_FormClosing({
        try { $uiTimer.Stop() } catch {}
    })

    [void]$form.ShowDialog()
}

if ($Install) {
    Write-Output (Install-TailscaleMtu)
    return
}

if ($Uninstall) {
    Write-Output (Uninstall-TailscaleMtu)
    return
}

if ($RunLoop) {
    Invoke-RunLoop
    return
}

if ($Apply) {
    $r = Invoke-Apply
    if ($r.Ok) { exit 0 } else { exit 1 }
}

if ($Status) {
    Write-Output (Write-StatusText)
    return
}

if ($UI -or (-not $Install -and -not $Uninstall -and -not $RunLoop -and -not $Apply -and -not $Status)) {
    Show-MtuGui
    return
}

