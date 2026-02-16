# SPDX-FileCopyrightText: Copyright (c) 2024-2026 Luiz Bizzio
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an administrator. Please run it again using 'Run as Administrator'." -ForegroundColor Red
    exit
}

$taskName = "Tailscale-MTU"
$taskDescription = "Adjust MTU for Tailscale interface"
$scriptCommand = "while (`$true) { try { Get-NetIPInterface -InterfaceAlias 'Tailscale' | Where-Object { `$_.NlMtu -ne 1500 } | ForEach-Object { Set-NetIPInterface -InterfaceAlias 'Tailscale' -NlMtuBytes 1500 }; Start-Sleep -Seconds 10 } catch { Start-Sleep -Seconds 10 } }"

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$scriptCommand`""

$trigger = New-ScheduledTaskTrigger -AtLogOn

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription -Force

Start-ScheduledTask -TaskName $taskName

Write-Host "Task Created."

Start-Sleep -Seconds 1

Write-Host "Verifying MTU for Tailscale interface..."

Start-Sleep -Seconds 2

netsh interface ipv4 show interfaces

Start-Sleep -Seconds 1

Write-Host "Setup complete."

