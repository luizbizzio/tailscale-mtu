#!/usr/bin/env bash
set -euo pipefail

PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

APP_NAME="tailscale-mtu"
SELF_URL="https://raw.githubusercontent.com/luizbizzio/tailscale-mtu/main/linux/linux-setup.sh"

INSTALL_PATH="/usr/local/bin/tailscale-mtu"
CONFIG_PATH="/etc/tailscale-mtu.conf"
RULE_PATH="/etc/udev/rules.d/99-tailscale-mtu.rules"

DEFAULT_IFACE="tailscale0"
DEFAULT_MTU="1280"

MIN_MTU="576"
WARN_IPV6_MTU="1280"
MAX_MTU="9000"

QUIET="0"
IP_BIN=""

die() { [ "$QUIET" = "1" ] || echo "Error: $*" >&2; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "Run as root. Use sudo."; }

is_int() {
  case "${1:-}" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

validate_iface() {
  local v="${1:-}"
  [ -n "$v" ] || die "Interface name cannot be empty"
  case "$v" in
    *[!a-zA-Z0-9_.:-]*) die "Invalid interface name: $v" ;;
  esac
}

validate_mtu() {
  local v="${1:-}"
  is_int "$v" || die "MTU must be a number: $v"
  [ "$v" -ge "$MIN_MTU" ] || die "MTU too low: $v (min $MIN_MTU)"
  [ "$v" -le "$MAX_MTU" ] || die "MTU too high: $v (max $MAX_MTU)"
}

warn_if_ipv6_risk() {
  local v="$1"
  if [ "$v" -lt "$WARN_IPV6_MTU" ]; then
    [ "$QUIET" = "1" ] || echo "Warning: MTU <$WARN_IPV6_MTU can break IPv6. You chose: $v" >&2
  fi
}

resolve_ip() {
  if [ -n "${IP_BIN:-}" ] && [ -x "${IP_BIN:-}" ]; then
    return 0
  fi

  local p=""
  p="$(command -v ip 2>/dev/null || true)"
  if [ -n "$p" ] && [ -x "$p" ]; then
    IP_BIN="$p"
    return 0
  fi

  for p in /usr/sbin/ip /usr/bin/ip /sbin/ip /bin/ip; do
    if [ -x "$p" ]; then
      IP_BIN="$p"
      return 0
    fi
  done

  return 1
}

need_ip() {
  resolve_ip || die "Missing required command: ip"
}

read_cfg() {
  local key="$1"
  if [ -f "$CONFIG_PATH" ]; then
    awk -F= -v k="$key" '$1==k {print $2}' "$CONFIG_PATH" | tail -n1 | tr -d '\r' || true
  fi
}

effective_iface() {
  local arg="${1:-}"
  if [ -n "$arg" ]; then echo "$arg"; return; fi
  local v
  v="$(read_cfg IFACE || true)"
  if [ -n "${v:-}" ]; then echo "$v"; else echo "$DEFAULT_IFACE"; fi
}

effective_mtu() {
  local arg="${1:-}"
  if [ -n "$arg" ]; then echo "$arg"; return; fi
  local v
  v="$(read_cfg MTU || true)"
  if [ -n "${v:-}" ]; then echo "$v"; else echo "$DEFAULT_MTU"; fi
}

write_cfg() {
  local iface="$1"
  local mtu="$2"
  cat > "$CONFIG_PATH" <<EOF
IFACE=$iface
MTU=$mtu
EOF
  chmod 644 "$CONFIG_PATH"
}

iface_exists() {
  "$IP_BIN" link show dev "$1" >/dev/null 2>&1
}

current_mtu() {
  "$IP_BIN" -o link show dev "$1" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}'
}

ensure_udev_dir() {
  mkdir -p "$(dirname "$RULE_PATH")"
}

udev_supported() {
  have_cmd udevadm && [ -d "/etc/udev" ]
}

reload_udev() {
  if udev_supported; then
    udevadm control --reload-rules >/dev/null 2>&1 || true
  fi
}

write_udev_rule() {
  local iface="$1"
  ensure_udev_dir
  cat > "$RULE_PATH" <<EOF
ACTION=="add|change", SUBSYSTEM=="net", KERNEL=="$iface", RUN+="$INSTALL_PATH --apply --udev"
EOF
  chmod 644 "$RULE_PATH"
}

apply_mtu_now() {
  local iface="$1"
  local mtu="$2"

  validate_iface "$iface"
  validate_mtu "$mtu"
  warn_if_ipv6_risk "$mtu"

  if ! iface_exists "$iface"; then
    return 2
  fi

  local before after
  before="$(current_mtu "$iface" || true)"

  if [ "${before:-}" = "$mtu" ]; then
    return 0
  fi

  "$IP_BIN" link set dev "$iface" mtu "$mtu"

  after="$(current_mtu "$iface" || true)"
  if [ "${after:-}" != "$mtu" ]; then
    die "Failed to apply MTU on $iface. Expected $mtu, got ${after:-unknown}"
  fi

  return 0
}

install_copy() {
  local src="$1"
  mkdir -p "$(dirname "$INSTALL_PATH")"
  if have_cmd install; then
    install -m 755 "$src" "$INSTALL_PATH"
  else
    cp -f "$src" "$INSTALL_PATH"
    chmod 755 "$INSTALL_PATH"
  fi
}

download_and_install() {
  local tmp
  tmp="$(mktemp)"
  if have_cmd curl; then
    curl -fsSL "$SELF_URL" -o "$tmp" || die "Failed to download: $SELF_URL"
  elif have_cmd wget; then
    wget -qO "$tmp" "$SELF_URL" || die "Failed to download: $SELF_URL"
  else
    rm -f "$tmp" || true
    die "Missing curl or wget"
  fi
  [ -s "$tmp" ] || die "Downloaded script is empty"
  install_copy "$tmp"
  rm -f "$tmp" || true
}

print_install_help() {
  cat <<EOF
Install:
  sudo bash linux-setup.sh

Recommended:
  curl -fsSLo /tmp/linux-setup.sh $SELF_URL && sudo bash /tmp/linux-setup.sh && rm -f /tmp/linux-setup.sh

Traditional (risky):
  curl -fsSL $SELF_URL | sudo bash

After install:
  sudo tailscale-mtu --mtu 1280
  tailscale-mtu --status
EOF
}

print_run_help() {
  cat <<EOF
Usage:
  sudo tailscale-mtu --mtu <${MIN_MTU}-${MAX_MTU}> [--iface tailscale0]
  sudo tailscale-mtu --apply
  tailscale-mtu --status
  sudo tailscale-mtu --uninstall
  tailscale-mtu --help

Notes:
  Linux MTU is per interface (IPv4 and IPv6 together).
  Persistence uses udev when available.
EOF
}

cmd_install() {
  require_root

  if [ $# -ne 0 ]; then
    print_install_help >&2
    die "Installer does not take flags."
  fi

  local src
  src="${BASH_SOURCE[0]:-${0:-}}"

  if [ -f "$src" ] && [ "$(basename "$src")" != "bash" ] && [ "$(basename "$src")" != "-" ]; then
    install_copy "$src"
  else
    download_and_install
  fi

  if [ ! -f "$CONFIG_PATH" ]; then
    write_cfg "$DEFAULT_IFACE" "$DEFAULT_MTU"
  fi

  if udev_supported; then
    local iface
    iface="$(effective_iface "")"
    validate_iface "$iface"
    write_udev_rule "$iface"
    reload_udev
    echo "Persistence: enabled (udev)"
  else
    echo "Persistence: disabled (udev not available)"
  fi

  echo "Installed: $INSTALL_PATH"
  echo "Config: $CONFIG_PATH"
  [ -f "$RULE_PATH" ] && echo "Udev rule: $RULE_PATH"
  echo "Next: sudo tailscale-mtu --mtu 1280"
}

cmd_uninstall() {
  require_root

  rm -f "$RULE_PATH" || true
  rm -f "$CONFIG_PATH" || true
  reload_udev || true

  if [ -f "$INSTALL_PATH" ]; then
    local self_real
    self_real="$(realpath "${0:-}" 2>/dev/null || echo "${0:-}")"
    if [ "$self_real" = "$INSTALL_PATH" ]; then
      nohup sh -c "sleep 1; rm -f '$INSTALL_PATH'" >/dev/null 2>&1 &
      echo "Uninstalled. Scheduled removal: $INSTALL_PATH"
    else
      rm -f "$INSTALL_PATH" || true
      echo "Uninstalled: $INSTALL_PATH"
    fi
  else
    echo "Uninstall: nothing to remove at $INSTALL_PATH"
  fi

  echo "Removed:"
  echo "  $RULE_PATH"
  echo "  $CONFIG_PATH"
  echo "  $INSTALL_PATH"
}

cmd_status() {
  local iface mtu
  iface="$(effective_iface "")"
  mtu="$(effective_mtu "")"

  echo "App: $APP_NAME"
  echo "Install path: $INSTALL_PATH"
  echo "Installed: $( [ -f "$INSTALL_PATH" ] && echo yes || echo no )"
  echo "Config path: $CONFIG_PATH"
  echo "Config: $( [ -f "$CONFIG_PATH" ] && echo yes || echo no )"
  echo "Udev rule path: $RULE_PATH"
  echo "Udev rule: $( [ -f "$RULE_PATH" ] && echo yes || echo no )"
  echo "Configured IFACE: $iface"
  echo "Configured MTU: $mtu"
  echo "Udev supported: $( udev_supported && echo yes || echo no )"

  if resolve_ip; then
    if iface_exists "$iface"; then
      local cur
      cur="$(current_mtu "$iface" || true)"
      echo "Interface: found ($iface)"
      echo "Current MTU: ${cur:-unknown}"
      if [ -n "${cur:-}" ] && [ "$cur" = "$mtu" ]; then
        echo "Match desired: yes"
      else
        echo "Match desired: no"
      fi
    else
      echo "Interface: not found ($iface)"
    fi
  else
    echo "ip command not found, cannot check current MTU."
  fi
}

cmd_apply() {
  local udev_mode="${1:-0}"

  if [ "$udev_mode" = "1" ]; then
    QUIET="1"
  fi

  need_ip

  local iface mtu
  iface="$(effective_iface "")"
  mtu="$(effective_mtu "")"

  if apply_mtu_now "$iface" "$mtu"; then
    [ "$udev_mode" = "1" ] || echo "Applied MTU $mtu on $iface"
    exit 0
  fi

  local rc=$?
  if [ "$udev_mode" = "1" ]; then
    exit 0
  fi

  if [ "$rc" -eq 2 ]; then
    echo "Interface not found right now: $iface" >&2
  fi
  exit "$rc"
}

cmd_set() {
  local iface_arg="$1"
  local mtu_arg="$2"

  need_ip
  require_root

  local iface mtu
  iface="$(effective_iface "$iface_arg")"
  mtu="$mtu_arg"

  validate_iface "$iface"
  validate_mtu "$mtu"
  warn_if_ipv6_risk "$mtu"

  write_cfg "$iface" "$mtu"

  local has_udev="0"
  if udev_supported; then
    write_udev_rule "$iface"
    reload_udev
    has_udev="1"
  else
    echo "Warning: udev not available. This will not persist across reboot." >&2
  fi

  if apply_mtu_now "$iface" "$mtu"; then
    echo "Applied MTU $mtu on $iface"
    echo "Saved config: $CONFIG_PATH"
    [ "$has_udev" = "1" ] && echo "Saved udev rule: $RULE_PATH"
    exit 0
  fi

  local rc=$?
  echo "Saved config: $CONFIG_PATH"
  [ "$has_udev" = "1" ] && echo "Saved udev rule: $RULE_PATH"

  if [ "$rc" -eq 2 ] && [ "$has_udev" = "1" ]; then
    echo "Interface not found right now: $iface"
    echo "It will apply automatically when the interface appears."
    exit 0
  fi

  if [ "$rc" -eq 2 ]; then
    echo "Interface not found right now: $iface" >&2
  fi
  exit "$rc"
}

main() {
  local self_basename
  self_basename="$(basename "${0:-}")"

  if [ "$self_basename" != "$APP_NAME" ] && [ "${0:-}" != "$INSTALL_PATH" ]; then
    case "${1:-}" in
      -h|--help) print_install_help; exit 0 ;;
    esac
    cmd_install "$@"
    exit 0
  fi

  local iface=""
  local mtu=""
  local want_status="0"
  local want_uninstall="0"
  local want_apply="0"
  local udev_mode="0"
  local want_help="0"

  while [ $# -gt 0 ]; do
    case "$1" in
      --iface) [ $# -ge 2 ] || die "Missing value for --iface"; iface="$2"; shift 2 ;;
      --mtu) [ $# -ge 2 ] || die "Missing value for --mtu"; mtu="$2"; shift 2 ;;
      --status) want_status="1"; shift ;;
      --uninstall) want_uninstall="1"; shift ;;
      --apply) want_apply="1"; shift ;;
      --udev) udev_mode="1"; shift ;;
      -h|--help) want_help="1"; shift ;;
      *) die "Unknown argument: $1" ;;
    esac
  done

  if [ "$want_help" = "1" ]; then
    print_run_help
    exit 0
  fi

  if [ "$want_status" = "1" ]; then
    cmd_status
    exit 0
  fi

  if [ "$want_uninstall" = "1" ]; then
    cmd_uninstall
    exit 0
  fi

  if [ "$want_apply" = "1" ]; then
    cmd_apply "$udev_mode"
    exit 0
  fi

  if [ -n "${mtu:-}" ] || [ -n "${iface:-}" ]; then
    [ -n "${mtu:-}" ] || die "Missing --mtu"
    cmd_set "$iface" "$mtu"
    exit 0
  fi

  print_run_help >&2
  exit 1
}

main "$@"
