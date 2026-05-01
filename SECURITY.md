# Security Policy

## Supported Versions

The project currently maintains the latest release on the `main` branch.

Only the most recent stable release is actively supported with security fixes. Older versions may not receive updates.

If you are running an outdated version, please upgrade before reporting a security issue.

---

## Reporting a Vulnerability

Please include:

- A clear description of the issue
- Steps to reproduce
- Affected operating system and version
- Tailscale version (if relevant)
- Any relevant logs or screenshots

You will receive an acknowledgment within 72 hours.

If the issue is confirmed, a fix will be prepared and released as soon as possible.

---

## Scope

This project interacts with:

- Network interface configuration
- MTU values
- Windows service execution
- Linux udev rules

Security considerations include:

- Avoiding privilege escalation beyond what is required
- Avoiding persistent unsafe configurations
- Not modifying system registry directly on Windows
- Not exposing network services or listening ports

The tool operates locally and does not transmit data externally.

---

## Responsible Disclosure

We follow responsible disclosure practices:

- Vulnerabilities are investigated privately
- Fixes are prepared before public disclosure
- Credit will be given to the reporter if desired

Please allow reasonable time for investigation and remediation before public discussion.

---

## Out of Scope

The following are considered out of scope:

- Misconfiguration by the user
- Incorrect MTU values chosen by the user
- Issues caused by third-party software, including Tailscale itself
- Performance tuning disagreements

---

## Security Philosophy

This project follows a minimal surface approach:

- No background network listeners
- No telemetry
- No automatic remote updates
- No registry manipulation
- Explicit privilege usage only when required

The goal is to keep the implementation simple, transparent, and auditable.

---

Thank you for helping improve the security of this project.

