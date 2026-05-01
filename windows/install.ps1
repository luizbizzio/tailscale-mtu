[CmdletBinding()]
param(
    [switch]$NoOpenUi
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$DefaultReleaseTag = 'v1.0.0'

if ([string]::IsNullOrWhiteSpace($DefaultReleaseTag) -or $DefaultReleaseTag -eq '__RELEASE_TAG__') {
    throw 'Default release tag was not filled. Run the GitHub Action before publishing install.ps1.'
}

$ReleaseBaseUrl = "https://github.com/luizbizzio/tailscale-mtu/releases/download/$DefaultReleaseTag"
$AppScriptUrl = "$ReleaseBaseUrl/tailscale-mtu.ps1"
$IconUrl = "$ReleaseBaseUrl/tailscale-mtu.ico"
$NssmUrl = "$ReleaseBaseUrl/nssm.exe"

function Write-Step {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )

    try {
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Message" -ForegroundColor $Color
    } catch {
        Write-Output $Message
    }
}

function Get-PowerShellExePath {
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $powershell) { return $powershell }
    return 'powershell.exe'
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

function ConvertTo-ArgumentList {
    param([string[]]$Arguments)

    $escaped = foreach ($arg in $Arguments) {
        if ($null -eq $arg) {
            '""'
        } elseif ($arg -match '[\s"]') {
            '"' + ($arg -replace '"', '\"') + '"'
        } else {
            $arg
        }
    }

    return ($escaped -join ' ')
}

function Start-InstalledUi {
    $appDir = Join-Path $env:ProgramData 'TailscaleMTU'
    $scriptPath = Join-Path $appDir 'tailscale-mtu.ps1'

    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "Installed script not found: $scriptPath"
    }

    $pwsh = Get-PowerShellExePath
    if (-not (Test-Path -LiteralPath $pwsh)) {
        throw "PowerShell executable not found: $pwsh"
    }

    $openVbsPath = Join-Path ([System.IO.Path]::GetTempPath()) ("Tailscale-MTU-Open-" + [guid]::NewGuid().ToString('N') + ".vbs")
    $command = '"' + $pwsh + '" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $scriptPath + '" -UI'
    $escapedCommand = $command.Replace('"', '""')

    $vbs = @"
Set sh = CreateObject("WScript.Shell")
WScript.Sleep 800
sh.Run "$escapedCommand", 0, False
"@

    Set-Content -LiteralPath $openVbsPath -Value $vbs -Encoding ASCII -Force

    Start-Process -FilePath "$env:WINDIR\System32\wscript.exe" -ArgumentList "`"$openVbsPath`"" -WindowStyle Hidden | Out-Null
    return $true
}

function New-BootstrapScript {
    param([string]$Path)

    $content = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [string]$IconPath,
    [Parameter(Mandatory = $true)]
    [string]$NssmPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

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

$AppDir = Join-Path $env:ProgramData 'TailscaleMTU'
$LogDir = Join-Path $AppDir 'logs'
$DestScriptPath = Join-Path $AppDir 'tailscale-mtu.ps1'
$DestIconPath = Join-Path $AppDir 'tailscale-mtu.ico'
$DestNssmPath = Join-Path $AppDir 'nssm.exe'

if (-not (Test-Path -LiteralPath $AppDir)) {
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "tailscale-mtu.ps1 was not found: $ScriptPath"
}

if (-not (Test-Path -LiteralPath $IconPath)) {
    throw "tailscale-mtu.ico was not found: $IconPath"
}

if (-not (Test-ExeLooksValid -Path $NssmPath)) {
    throw "nssm.exe is missing or invalid: $NssmPath"
}

Copy-Item -LiteralPath $ScriptPath -Destination $DestScriptPath -Force
Copy-Item -LiteralPath $IconPath -Destination $DestIconPath -Force

if (Test-Path -LiteralPath $DestNssmPath) {
    Write-Output "Existing nssm.exe found. Keeping it because the service may be using it."
} else {
    Copy-Item -LiteralPath $NssmPath -Destination $DestNssmPath -Force
    if (-not (Test-ExeLooksValid -Path $DestNssmPath)) {
        throw "Installed nssm.exe is missing or invalid: $DestNssmPath"
    }
}

if (-not (Test-Path -LiteralPath $DestScriptPath)) {
    throw "Installed script was not staged: $DestScriptPath"
}

if (-not (Test-Path -LiteralPath $DestIconPath)) {
    throw "Installed icon was not staged: $DestIconPath"
}

$pwsh = Get-PowerShellExePath
$installArgs = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $DestScriptPath,
    '-Install',
    '-NoOpenUi'
)

$installOutput = & $pwsh @installArgs 2>&1
$installExitCode = $LASTEXITCODE

foreach ($line in $installOutput) {
    $text = [string]$line
    if ($text -eq 'UI: not opened because -NoOpenUi was used.') {
        continue
    }

    Write-Output $line
}

exit $installExitCode
'@

    Set-Content -LiteralPath $Path -Value $content -Encoding UTF8 -Force
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
} catch {
}

$tmpBase = "Tailscale-MTU-" + [guid]::NewGuid().ToString('N')
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) $tmpBase
$tmpScript = Join-Path $tmpDir 'tailscale-mtu.ps1'
$tmpIcon = Join-Path $tmpDir 'tailscale-mtu.ico'
$tmpNssm = Join-Path $tmpDir 'nssm.exe'
$tmpBootstrap = Join-Path $tmpDir 'bootstrap.ps1'

try {
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    Write-Step "Selected release: $DefaultReleaseTag"
    Write-Step 'Downloading release assets...'

    Write-Step 'Downloading tailscale-mtu.ps1...'
    Invoke-WebRequest -Uri $AppScriptUrl -OutFile $tmpScript -UseBasicParsing -ErrorAction Stop

    Write-Step 'Downloading tailscale-mtu.ico...'
    Invoke-WebRequest -Uri $IconUrl -OutFile $tmpIcon -UseBasicParsing -ErrorAction Stop

    Write-Step 'Downloading nssm.exe...'
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

    Write-Step 'Assets downloaded. Starting installer...' Green

    New-BootstrapScript -Path $tmpBootstrap

    $pwsh = Get-PowerShellExePath

    $bootstrapArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $tmpBootstrap,
        '-ScriptPath', $tmpScript,
        '-IconPath', $tmpIcon,
        '-NssmPath', $tmpNssm
    )

    if (Test-IsAdmin) {
        & $pwsh @bootstrapArgs
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        $p = Start-Process -FilePath $pwsh -ArgumentList (ConvertTo-ArgumentList -Arguments $bootstrapArgs) -Verb RunAs -Wait -PassThru
        if ($p.ExitCode -ne 0) { exit $p.ExitCode }
    }

    if (-not $NoOpenUi) {
        Write-Step 'Opening Tailscale MTU...' Green
        Start-InstalledUi | Out-Null
    }
} finally {
    try {
        if (Test-Path -LiteralPath $tmpDir) {
            Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
    }
}
