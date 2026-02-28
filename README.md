# Tailscale MTU 🌐

Persistent MTU management for Tailscale across reboots and interface resets.

This project helps you save the MTU you want and keep it applied after interface changes, reconnects, and reboots.

<p align="center">
  <img src="/images/tailscale-logo.png?asd" alt="Tailscale MTU" width="600" />
</p>

## What it does

- Keeps your Tailscale MTU persistent
- Supports IPv4 and IPv6 values separately (Windows Only)
- Works on Linux and Windows
- On Windows, runs with a simple UI after install

## Why this exists

Tailscale MTU can go back to another value after reconnects or reboot.
This tool saves your desired value and keeps checking in the background.
If the interface changes, it applies the saved MTU again.

## Install

### Windows 🪟

Run this in **PowerShell** or in **CMD / Windows Terminal**:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy -Scope Process Bypass -Force; $ProgressPreference='SilentlyContinue'; $u='https://raw.githubusercontent.com/luizbizzio/tailscale-mtu/main/windows/windows-setup.ps1'; $c=(Invoke-WebRequest -UseBasicParsing $u).Content; & ([ScriptBlock]::Create($c)) -Install"
```

After install:

1. Open **Tailscale MTU** from the Start Menu
2. Set your values
3. Click **Save and Apply**

Default Windows files:

```text
%ProgramData%\TailscaleMTU\config.json
%ProgramData%\TailscaleMTU\state.json
```

<p align="center">
  <img src="/images/screenshot-windows.png" alt="Tailscale MTU Windows UI" width="700" />
</p>

---

### Linux 🐧

```bash
curl -fsSL https://raw.githubusercontent.com/luizbizzio/tailscale-mtu/main/linux/linux-setup.sh | sudo bash
```

After install, set the MTU like this:

```bash
sudo tailscale-mtu --mtu 1280
```

Optional interface:

```bash
sudo tailscale-mtu --mtu 1280 --iface tailscale0
```

Check status:

```bash
tailscale-mtu --status
```

---

## How it works

### Linux

The installer places the binary at:

```text
/usr/local/bin/tailscale-mtu
```

When you run:

```bash
sudo tailscale-mtu --mtu 1280
```

It:

- Saves the MTU and interface in `/etc/tailscale-mtu.conf`
- Applies the MTU immediately using `ip link set`
- Creates a `udev` rule (if available) to reapply MTU when the interface returns

#### Linux limits

- Linux uses **one MTU value per interface**
- IPv4 and IPv6 are **not separate**
- Allowed range: **576 to 9000**
- Values below **1280** trigger a warning

Why **1280** matters:

- **1280 bytes is the minimum MTU required by IPv6 (RFC 8200)**
- Lower values can cause IPv6 fragmentation failures and dropped traffic

In practice:

```text
Save MTU -> apply immediately -> udev reapplies on reconnect
```

---

### Windows

The installer places all files under:

```text
%ProgramData%\TailscaleMTU
```

What happens internally:

- Uses `netsh` to configure IPv4 and IPv6 MTU independently
- Runs as a Windows Service via **NSSM**
- Periodically verifies the interface state
- Reapplies MTU automatically after reboots or reconnects
- Does not modify the registry directly

---

## License 📄

This project is licensed under the [Mozilla Public License 2.0](./LICENSE).
