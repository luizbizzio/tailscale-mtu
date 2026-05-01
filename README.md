<h1 align="center">Tailscale MTU 🌐</h1>

<p align="center">Persistent MTU management for Tailscale across reboots, reconnects, and interface resets.</p>
<p align="center">Save your preferred MTU and keep it applied automatically when Tailscale or Windows resets the interface.</p>

<p align="center">
  <img src="/images/tailscale-mtu.png" alt="Tailscale MTU" width="600" />
</p>

## What it does

- Keeps your Tailscale MTU persistent
- Supports separate IPv4 and IPv6 MTU values on Windows
- Supports Linux and Windows
- Provides a simple Windows UI after install
- Runs as a Windows Service on Windows
- Applies the saved MTU immediately when changed, then keeps monitoring in the background
- Reapplies the saved MTU when Tailscale or Windows resets the interface

## Why this exists

Tailscale MTU can return to another value after reconnects, interface resets, driver changes, or reboots.

This tool saves your desired MTU, applies it immediately, and keeps checking in the background. If the Tailscale interface changes, it applies the saved MTU again.

## Install

### Windows 🪟

Install the latest Windows release:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://github.com/luizbizzio/tailscale-mtu/releases/latest/download/install.ps1' | iex"
```

After install:

1. Open **Tailscale MTU** from the Start Menu
2. Set your IPv4 and IPv6 MTU values
3. Click **Save and Apply**

Default Windows files:

```text
%ProgramData%\TailscaleMTU\
  tailscale-mtu.ps1
  tailscale-mtu.ico
  nssm.exe
  TailscaleMTULauncher.vbs
  config.json
  state.json
  logs\
    service.out.log
    service.err.log

%ProgramData%\Microsoft\Windows\Start Menu\Programs\Tailscale MTU.lnk
```

<p align="center">
  <img src="/images/screenshot-windows.png" alt="Tailscale MTU Windows" width="700" />
</p>

#### Windows command line

```powershell
.\tailscale-mtu.ps1 -Status
.\tailscale-mtu.ps1 -Version
.\tailscale-mtu.ps1 -IPv4 1280 -IPv6 1280 -Enable
.\tailscale-mtu.ps1 -IPv4 1280 -IPv6 1280 -Interval 60 -Enable
.\tailscale-mtu.ps1 -Apply
.\tailscale-mtu.ps1 -Disable
.\tailscale-mtu.ps1 -CheckUpdate
.\tailscale-mtu.ps1 -Update
.\tailscale-mtu.ps1 -Repair
.\tailscale-mtu.ps1 -Uninstall
.\tailscale-mtu.ps1 -Uninstall -Purge
```

`-Status` prints machine-readable JSON, which is useful for automation and integrations.

Windows requires administrator rights because MTU changes use `netsh` and the installer creates a Windows Service.

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

The installer places the command at:

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
- Creates a `udev` rule, when available, to reapply MTU when the interface returns

#### Linux limits

- Linux uses one MTU value per interface
- IPv4 and IPv6 are not separate
- Allowed range: 576 to 9000
- Values below 1280 trigger a warning

Why 1280 matters:

- 1280 bytes is the minimum MTU required by IPv6, as defined by RFC 8200
- Lower values can cause IPv6 fragmentation issues and dropped traffic

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
- Runs as the `TailscaleMTU` Windows Service through NSSM
- Applies saved MTU values immediately when the configuration changes
- Periodically verifies the interface state
- Reapplies MTU automatically after reboots or reconnects
- Does not modify the registry directly

The Windows release assets are:

```text
install.ps1
tailscale-mtu.ps1
tailscale-mtu.ico
nssm.exe
```

## Recommended MTU

The default value is:

```text
1280
```

This is conservative and works well for Tailscale paths where fragmentation, relays, VPN stacking, or unusual network conditions can reduce the effective path MTU.

You can use a higher value if your network path supports it, but 1280 is the safer default.

## Troubleshooting

Check status:

```powershell
.\tailscale-mtu.ps1 -Status
```

Repair the Windows installation:

```powershell
.\tailscale-mtu.ps1 -Repair
```

If MTU is not being applied, check that Tailscale is installed, the Tailscale interface exists, and the `TailscaleMTU` service is running.

Service logs are stored in:

```text
%ProgramData%\TailscaleMTU\logs\
```

## License 📄

This project is licensed under the [Mozilla Public License 2.0](./LICENSE).
