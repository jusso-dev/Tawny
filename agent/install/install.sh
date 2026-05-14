#!/usr/bin/env bash
set -euo pipefail

backend_url=""
enrollment_token=""
download_url=""
sha256=""
install_dir="/usr/local/tawny"
config_path="/Library/Application Support/Tawny/config.toml"
dry_run=0

usage() {
  cat <<'USAGE'
Usage: install.sh --backend-url URL --enrollment-token TOKEN [options]

Options:
  --download-url URL   Agent binary URL. Defaults to the latest GitHub release asset for this Mac.
  --sha256 HASH        Expected SHA-256. Defaults to the latest release .sha256 sidecar when available.
  --install-dir DIR    Binary install directory. Default: /usr/local/tawny
  --config-path PATH   Config file path. Default: /Library/Application Support/Tawny/config.toml
  --dry-run            Print actions without writing files, downloading, or registering launchd.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-url) backend_url="${2:-}"; shift 2 ;;
    --enrollment-token) enrollment_token="${2:-}"; shift 2 ;;
    --download-url) download_url="${2:-}"; shift 2 ;;
    --sha256) sha256="${2:-}"; shift 2 ;;
    --install-dir) install_dir="${2:-}"; shift 2 ;;
    --config-path) config_path="${2:-}"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$backend_url" || -z "$enrollment_token" ]]; then
  usage >&2
  exit 2
fi

run() {
  if [[ "$dry_run" -eq 1 ]]; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

latest_asset_url() {
  local pattern="$1"
  python3 - "$pattern" <<'PY'
import json
import re
import sys
import urllib.request

pattern = re.compile(sys.argv[1])
req = urllib.request.Request(
    "https://api.github.com/repos/jusso-dev/Tawny/releases/latest",
    headers={"User-Agent": "tawny-install"},
)
with urllib.request.urlopen(req) as res:
    release = json.load(res)
for asset in release.get("assets", []):
    if pattern.search(asset.get("name", "")):
        print(asset["browser_download_url"])
        sys.exit(0)
sys.exit(1)
PY
}

arch="$(uname -m)"
case "$arch" in
  arm64|aarch64) platform="macos-arm64" ;;
  x86_64|amd64) platform="macos-x64" ;;
  *) echo "Unsupported macOS architecture: $arch" >&2; exit 1 ;;
esac

if [[ -z "$download_url" && "$dry_run" -eq 0 ]]; then
  download_url="$(latest_asset_url "${platform}$")" || {
    echo "No latest release asset found for $platform. Pass --download-url." >&2
    exit 1
  }
fi

if [[ -z "$sha256" && "$dry_run" -eq 0 ]]; then
  sha_url="$(latest_asset_url "${platform}\\.sha256$" || true)"
  if [[ -n "$sha_url" ]]; then
    sha256="$(curl -fsSL "$sha_url" | awk '{print $1}')"
  fi
fi

binary_path="$install_dir/tawny-agent"
config_dir="$(dirname "$config_path")"
plist_path="/Library/LaunchDaemons/dev.jusso.tawny-agent.plist"

run mkdir -p "$install_dir" "$config_dir"

if [[ "$dry_run" -eq 1 ]]; then
  printf '[dry-run] curl -fsSL %s -o %s\n' "${download_url:-<latest release asset>}" "$binary_path"
else
  curl -fsSL "$download_url" -o "$binary_path"
  chmod 0755 "$binary_path"
fi

if [[ -n "$sha256" ]]; then
  if [[ "$dry_run" -eq 1 ]]; then
    printf '[dry-run] verify SHA-256 %s for %s\n' "$sha256" "$binary_path"
  else
    actual="$(shasum -a 256 "$binary_path" | awk '{print $1}')"
    actual_lower="$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')"
    expected_lower="$(printf '%s' "$sha256" | tr '[:upper:]' '[:lower:]')"
    if [[ "$actual_lower" != "$expected_lower" ]]; then
      echo "SHA-256 mismatch. Expected $sha256, got $actual." >&2
      exit 1
    fi
  fi
else
  printf 'Skipping SHA-256 verification because no hash was provided.\n'
fi

if [[ "$dry_run" -eq 1 ]]; then
  printf '[dry-run] write %s\n' "$config_path"
else
  cat > "$config_path" <<EOF
[backend]
url = "$backend_url"
enrollment_token = "$enrollment_token"

[collection]
heartbeat_interval_seconds = 60
process_interval_seconds = 30
network_interval_seconds = 30
users_interval_seconds = 300
system_interval_seconds = 3600
fim_interval_seconds = 300
max_in_memory_events = 1000
spill_path = "$config_path.spool"
fim_paths = []
EOF
fi

if [[ "$dry_run" -eq 1 ]]; then
  printf '[dry-run] write and bootstrap launchd job %s\n' "$plist_path"
else
  cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.jusso.tawny-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$binary_path</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/tawny-agent.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/tawny-agent.err</string>
</dict>
</plist>
EOF
  chown root:wheel "$plist_path"
  chmod 0644 "$plist_path"
  launchctl bootout system "$plist_path" >/dev/null 2>&1 || true
  launchctl bootstrap system "$plist_path"
  launchctl kickstart -k system/dev.jusso.tawny-agent
fi
