#!/usr/bin/env bash
set -euo pipefail

backend_url=""
enrollment_token=""
download_url=""
source_binary_path=""
sha256=""
install_dir=""
config_path=""
state_dir=""
service_scope="system"
dry_run=0
allow_insecure_http=0
skip_attestation=0
candidate=""
config_candidate=""
rollback_needed=0
binary_path=""
backup_path=""
os_family=""

usage() {
  cat <<'USAGE'
Usage:
  install.sh --backend-url URL --enrollment-token TOKEN [options]
  install.sh --config-path EXISTING_CONFIG [options]

Options:
  --download-url URL          HTTPS agent binary URL. Defaults to latest GitHub release asset.
  --binary-path PATH          Local agent binary. Requires --sha256.
  --sha256 HASH               Expected SHA-256. Required for explicit download URLs.
  --install-dir DIR           Binary install directory. Default: /usr/local/tawny
  --config-path PATH          Config path. Default: platform system path.
  --state-dir DIR             State directory. Default: platform system path.
  --user                      Install a per-user macOS LaunchAgent.
  --allow-insecure-http       Allow an HTTP backend URL. Intended only for isolated development.
  --skip-attestation          Skip GitHub artifact attestation verification. Not for production.
  --dry-run                   Print actions without changing the host.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-url) backend_url="${2:-}"; shift 2 ;;
    --enrollment-token) enrollment_token="${2:-}"; shift 2 ;;
    --download-url) download_url="${2:-}"; shift 2 ;;
    --binary-path) source_binary_path="${2:-}"; shift 2 ;;
    --sha256) sha256="${2:-}"; shift 2 ;;
    --install-dir) install_dir="${2:-}"; shift 2 ;;
    --config-path) config_path="${2:-}"; shift 2 ;;
    --state-dir) state_dir="${2:-}"; shift 2 ;;
    --user) service_scope="user"; shift ;;
    --allow-insecure-http) allow_insecure_http=1; shift ;;
    --skip-attestation) skip_attestation=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

explicit_download_url=0
if [[ -n "$download_url" ]]; then
  explicit_download_url=1
fi

os_name="$(uname -s)"
case "$os_name" in
  Darwin)
    os_family="macos"
    if [[ "$service_scope" == "user" ]]; then
      default_config_path="$HOME/.config/tawny/config.toml"
      : "${state_dir:=$HOME/.local/state/tawny}"
      : "${install_dir:=$HOME/.local/bin}"
      plist_path="$HOME/Library/LaunchAgents/dev.jusso.tawny-agent.plist"
      launchd_domain="gui/$(id -u)"
    else
      default_config_path="/Library/Application Support/Tawny/config.toml"
      : "${state_dir:=/Library/Application Support/Tawny}"
      : "${install_dir:=/usr/local/tawny}"
      plist_path="/Library/LaunchDaemons/dev.jusso.tawny-agent.plist"
      launchd_domain="system"
    fi
    ;;
  Linux)
    if [[ "$service_scope" == "user" ]]; then
      echo "--user is currently supported only on macOS." >&2
      exit 2
    fi
    os_family="linux"
    default_config_path="/etc/tawny/config.toml"
    : "${state_dir:=/var/lib/tawny}"
    : "${install_dir:=/usr/local/tawny}"
    ;;
  *)
    echo "Unsupported operating system: $os_name" >&2
    exit 1
    ;;
esac

if [[ -z "$config_path" ]]; then
  config_path="$default_config_path"
fi
if [[ -z "$install_dir" || "$install_dir" == "/" || -z "$config_path" || "$config_path" == "/" ||
      -z "$state_dir" || "$state_dir" == "/" ]]; then
  echo "Install, config, and state paths must not be filesystem root." >&2
  exit 2
fi
if [[ ! -f "$config_path" && ( -z "$backend_url" || -z "$enrollment_token" ) ]]; then
  echo "--backend-url and --enrollment-token are required for a new installation." >&2
  exit 2
fi
if [[ -n "$backend_url" && "$backend_url" != https://* && "$allow_insecure_http" -ne 1 ]]; then
  echo "Backend URL must use HTTPS. Use --allow-insecure-http only for isolated development." >&2
  exit 2
fi
if [[ "$backend_url" == *$'\n'* || "$backend_url" == *$'\r'* ||
      "$enrollment_token" == *$'\n'* || "$enrollment_token" == *$'\r'* ]]; then
  echo "Backend URL and enrollment token must be single-line values." >&2
  exit 2
fi
if [[ -n "$download_url" && -n "$source_binary_path" ]]; then
  echo "--download-url and --binary-path are mutually exclusive." >&2
  exit 2
fi
if [[ -n "$source_binary_path" && ! -f "$source_binary_path" ]]; then
  echo "Local agent binary does not exist: $source_binary_path" >&2
  exit 2
fi
if [[ -n "$source_binary_path" && -z "$sha256" ]]; then
  echo "--sha256 is required with --binary-path." >&2
  exit 2
fi
if [[ "$dry_run" -ne 1 && "$service_scope" == "system" && "$(id -u)" -ne 0 ]]; then
  echo "Run installer as root (for example, sudo install.sh ...)." >&2
  exit 1
fi

run() {
  if [[ "$dry_run" -eq 1 ]]; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

download() {
  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 --retry 3 --retry-all-errors \
    --connect-timeout 15 --max-time 300 "$1" -o "$2"
}

latest_asset_url() {
  local pattern="$1"
  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 --retry 3 --retry-all-errors \
    --connect-timeout 15 --max-time 60 \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: tawny-install" \
    "https://api.github.com/repos/jusso-dev/Tawny/releases/latest" |
    python3 -c '
import json, re, sys
pattern = re.compile(sys.argv[1])
for asset in json.load(sys.stdin).get("assets", []):
    if pattern.search(asset.get("name", "")):
        print(asset["browser_download_url"])
        raise SystemExit(0)
raise SystemExit(1)
' "$pattern"
}

toml_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

rollback() {
  local status=$?
  rm -f "${candidate:-}"
  rm -f "${config_candidate:-}"
  if [[ "$rollback_needed" -eq 1 && -n "$backup_path" && -f "$backup_path" ]]; then
    echo "Install failed; restoring previous agent binary." >&2
    if [[ "$os_family" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl stop tawny-agent.service >/dev/null 2>&1 || true
    elif [[ "$os_family" == "macos" ]]; then
      launchctl bootout "$launchd_domain/dev.jusso.tawny-agent" >/dev/null 2>&1 || true
    fi
    mv -f "$backup_path" "$binary_path"
    if [[ "$os_family" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl start tawny-agent.service >/dev/null 2>&1 || true
    elif [[ "$os_family" == "macos" ]]; then
      launchctl bootstrap "$launchd_domain" "$plist_path" >/dev/null 2>&1 || true
    fi
  elif [[ "$rollback_needed" -eq 2 && -n "$binary_path" ]]; then
    rm -f "$binary_path"
  fi
  exit "$status"
}
trap rollback ERR INT TERM

arch="$(uname -m)"
case "$os_family:$arch" in
  macos:arm64|macos:aarch64) platform="macos-arm64" ;;
  macos:x86_64|macos:amd64) platform="macos-x64" ;;
  linux:arm64|linux:aarch64) platform="linux-arm64" ;;
  linux:x86_64|linux:amd64) platform="linux-x64" ;;
  *) echo "Unsupported ${os_family} architecture: $arch" >&2; exit 1 ;;
esac

if [[ -z "$download_url" && -z "$source_binary_path" && "$dry_run" -eq 0 ]]; then
  download_url="$(latest_asset_url "${platform}$")" || {
    echo "No latest release asset found for $platform." >&2
    exit 1
  }
fi
if [[ -n "$download_url" && "$download_url" != https://* ]]; then
  echo "Agent download URL must use HTTPS." >&2
  exit 2
fi
if [[ "$explicit_download_url" -eq 1 && -z "$sha256" ]]; then
  echo "--sha256 is required with --download-url." >&2
  exit 2
fi
if [[ -z "$sha256" && -z "$source_binary_path" && "$dry_run" -eq 0 ]]; then
  sha_url="$(latest_asset_url "${platform}\\.sha256$")" || {
    echo "Release is missing mandatory SHA-256 sidecar for $platform." >&2
    exit 1
  }
  sha_file="$(mktemp)"
  candidate="$sha_file"
  download "$sha_url" "$sha_file"
  sha256="$(awk 'NR == 1 { print $1 }' "$sha_file")"
  rm -f "$sha_file"
  candidate=""
fi
if [[ "$dry_run" -ne 1 && ! "$sha256" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "A valid 64-character SHA-256 is required." >&2
  exit 2
fi

binary_path="$install_dir/tawny-agent"
backup_path="$install_dir/tawny-agent.previous"
config_dir="$(dirname "$config_path")"

run mkdir -p "$install_dir" "$config_dir" "$state_dir"
if [[ "$os_family" == "linux" ]]; then
  if [[ "$dry_run" -eq 1 ]]; then
    printf '[dry-run] create locked system account tawny when absent\n'
  else
    getent group tawny >/dev/null 2>&1 || groupadd --system tawny
    id tawny >/dev/null 2>&1 ||
      useradd --system --gid tawny --home-dir "$state_dir" --shell /usr/sbin/nologin tawny
    if [[ "$config_dir" == "/etc/tawny" ]]; then
      chown root:tawny "$config_dir"
      chmod 0750 "$config_dir"
    fi
    chown tawny:tawny "$state_dir"
    chmod 0750 "$state_dir"
  fi
else
  if [[ "$service_scope" == "system" ]]; then
    run chown root:wheel "$state_dir"
  fi
  run chmod 0700 "$state_dir"
fi

if [[ "$dry_run" -eq 1 ]]; then
  printf '[dry-run] stage, verify SHA-256, and verify GitHub attestation for %s\n' \
    "${source_binary_path:-${download_url:-<latest release asset>}}"
else
  candidate="$(mktemp "$install_dir/.tawny-agent.XXXXXX")"
  if [[ -n "$source_binary_path" ]]; then
    install -m 0755 "$source_binary_path" "$candidate"
  else
    download "$download_url" "$candidate"
  fi
  if command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$candidate" | awk '{print $1}')"
  else
    actual="$(sha256sum "$candidate" | awk '{print $1}')"
  fi
  actual_lower="$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')"
  expected_lower="$(printf '%s' "$sha256" | tr '[:upper:]' '[:lower:]')"
  if [[ "$actual_lower" != "$expected_lower" ]]; then
    echo "SHA-256 mismatch. Expected $sha256, got $actual." >&2
    exit 1
  fi
  if [[ "$skip_attestation" -ne 1 ]]; then
    if ! command -v gh >/dev/null 2>&1; then
      echo "GitHub CLI is required for artifact attestation verification." >&2
      echo "Install gh, or use --skip-attestation only under an approved exception." >&2
      exit 1
    fi
    gh attestation verify "$candidate" --repo jusso-dev/Tawny >/dev/null
  fi
  chmod 0755 "$candidate"
fi

if [[ ! -e "$config_path" ]]; then
  escaped_backend_url="$(toml_escape "$backend_url")"
  escaped_enrollment_token="$(toml_escape "$enrollment_token")"
  escaped_spill_path="$(toml_escape "$state_dir/events.spool")"
  if [[ "$dry_run" -eq 1 ]]; then
    printf '[dry-run] atomically create %s with restricted permissions\n' "$config_path"
  else
    config_candidate="$(mktemp "$config_dir/.config.toml.XXXXXX")"
    chmod 0600 "$config_candidate"
    {
      printf '[backend]\n'
      printf 'url = "%s"\n' "$escaped_backend_url"
      printf 'enrollment_token = "%s"\n\n' "$escaped_enrollment_token"
      printf '[collection]\n'
      printf 'heartbeat_interval_seconds = 60\n'
      printf 'process_interval_seconds = 30\n'
      printf 'process_events_interval_seconds = 5\n'
      printf 'network_interval_seconds = 30\n'
      printf 'users_interval_seconds = 300\n'
      printf 'system_interval_seconds = 3600\n'
      printf 'fim_interval_seconds = 300\n'
      printf 'fs_events_interval_seconds = 5\n'
      printf 'dns_interval_seconds = 30\n'
      printf 'supply_chain_interval_seconds = 21600\n'
      printf 'max_in_memory_events = 1000\n'
      printf 'max_spool_bytes = 268435456\n'
      printf 'http_timeout_seconds = 30\n'
      printf 'max_retry_backoff_seconds = 300\n'
      printf 'spill_path = "%s"\n' "$escaped_spill_path"
      printf 'fim_paths = []\n'
    } > "$config_candidate"
    mv -f "$config_candidate" "$config_path"
    if [[ "$os_family" == "linux" ]]; then
      chown root:tawny "$config_path"
      chmod 0640 "$config_path"
    else
      if [[ "$service_scope" == "system" ]]; then
        chown root:wheel "$config_path"
      fi
      chmod 0600 "$config_path"
    fi
  fi
else
  printf 'Preserving existing config: %s\n' "$config_path"
  if [[ "$dry_run" -ne 1 && "$os_family" == "linux" ]]; then
    legacy_spill_path="$config_path.spool"
    config_candidate="$(mktemp "$config_dir/.config.toml.XXXXXX")"
    awk -v old="$legacy_spill_path" -v new="$state_dir/events.spool" '
      $0 == "spill_path = \"" old "\"" {
        print "spill_path = \"" new "\""
        next
      }
      { print }
    ' "$config_path" > "$config_candidate"
    chmod 0640 "$config_candidate"
    chown root:tawny "$config_candidate"
    mv -f "$config_candidate" "$config_path"
    config_candidate=""
  elif [[ "$dry_run" -ne 1 ]]; then
    if [[ "$service_scope" == "system" ]]; then
      chown root:wheel "$config_path"
    fi
    chmod 0600 "$config_path"
  fi
fi

if [[ "$dry_run" -ne 1 ]]; then
  rm -f "$backup_path"
  if [[ -f "$binary_path" ]]; then
    mv "$binary_path" "$backup_path"
    rollback_needed=1
  else
    rollback_needed=2
  fi
  mv "$candidate" "$binary_path"
  candidate=""
fi

if [[ "$os_family" == "macos" ]]; then
  if [[ "$dry_run" -eq 1 ]]; then
    printf '[dry-run] write and bootstrap %s launchd job %s\n' "$service_scope" "$plist_path"
  else
    mkdir -p "$(dirname "$plist_path")"
    plist_candidate="$(mktemp "$(dirname "$plist_path")/.tawny-agent.plist.XXXXXX")"
    cat > "$plist_candidate" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.jusso.tawny-agent</string>
  <key>ProgramArguments</key>
  <array><string>$binary_path</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>TAWNY_CONFIG</key><string>$config_path</string>
    <key>TAWNY_STATE_PATH</key><string>$state_dir/state.toml</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>Umask</key><integer>27</integer>
  <key>StandardOutPath</key><string>$state_dir/agent.log</string>
  <key>StandardErrorPath</key><string>$state_dir/agent.err</string>
</dict>
</plist>
EOF
    plutil -lint "$plist_candidate" >/dev/null
    if [[ "$service_scope" == "system" ]]; then
      chown root:wheel "$plist_candidate"
    fi
    chmod 0644 "$plist_candidate"
    mv -f "$plist_candidate" "$plist_path"
    launchctl bootout "$launchd_domain/dev.jusso.tawny-agent" >/dev/null 2>&1 || true
    launchctl bootstrap "$launchd_domain" "$plist_path"
    launchctl kickstart -k "$launchd_domain/dev.jusso.tawny-agent"
    launchctl print "$launchd_domain/dev.jusso.tawny-agent" >/dev/null
  fi
else
  service_path="/etc/systemd/system/tawny-agent.service"
  if [[ "$dry_run" -eq 1 ]]; then
    printf '[dry-run] write and enable hardened systemd service %s\n' "$service_path"
  else
    service_candidate="$(mktemp --suffix=.service "$(dirname "$service_path")/tawny-agent.XXXXXX")"
    cat > "$service_candidate" <<EOF
[Unit]
Description=Tawny endpoint agent
Documentation=https://github.com/jusso-dev/Tawny
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=tawny
Group=tawny
Environment="TAWNY_CONFIG=$config_path"
Environment="TAWNY_STATE_PATH=$state_dir/state.toml"
ExecStart="$binary_path"
Restart=on-failure
RestartSec=5
UMask=0027
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=read-only
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ReadWritePaths="$state_dir"
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
    systemd-analyze verify "$service_candidate"
    chown root:root "$service_candidate"
    chmod 0644 "$service_candidate"
    mv -f "$service_candidate" "$service_path"
    systemctl daemon-reload
    systemctl enable tawny-agent.service
    systemctl restart tawny-agent.service
    systemctl is-active --quiet tawny-agent.service
  fi
fi

rollback_needed=0
trap - ERR INT TERM
printf 'Tawny agent installed successfully. Previous binary retained at %s when upgraded.\n' "$backup_path"
