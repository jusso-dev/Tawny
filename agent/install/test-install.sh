#!/usr/bin/env bash
set -euo pipefail

installer="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

install_dir="$test_dir/bin"
config_path="$test_dir/config/config.toml"
state_dir="$test_dir/state"
local_binary="$test_dir/tawny-agent"

mkdir -p "$(dirname "$config_path")"
printf '#!/usr/bin/env sh\nexit 0\n' > "$local_binary"
chmod 0755 "$local_binary"
printf '[backend]\nurl = "https://example.invalid"\n' > "$config_path"

if command -v shasum >/dev/null 2>&1; then
  sha256="$(shasum -a 256 "$local_binary" | awk '{print $1}')"
else
  sha256="$(sha256sum "$local_binary" | awk '{print $1}')"
fi

output="$(
  bash "$installer" \
    --install-dir "$install_dir" \
    --config-path "$config_path" \
    --state-dir "$state_dir" \
    --binary-path "$local_binary" \
    --sha256 "$sha256" \
    --skip-attestation \
    --dry-run
)"
grep -F "Preserving existing config: $config_path" <<< "$output" >/dev/null

new_config="$test_dir/new/config.toml"
if bash "$installer" \
  --install-dir "$install_dir" \
  --config-path "$new_config" \
  --state-dir "$state_dir" \
  --binary-path "$local_binary" \
  --sha256 "$sha256" \
  --skip-attestation \
  --dry-run >/dev/null 2>&1; then
  echo "installer accepted a new installation without enrollment credentials" >&2
  exit 1
fi

if bash "$installer" \
  --install-dir "$install_dir" \
  --config-path "$config_path" \
  --state-dir "$state_dir" \
  --binary-path "$local_binary" \
  --skip-attestation \
  --dry-run >/dev/null 2>&1; then
  echo "installer accepted a local binary without a checksum" >&2
  exit 1
fi

if bash "$installer" \
  --install-dir "$install_dir" \
  --config-path "$config_path" \
  --state-dir "$state_dir" \
  --binary-path "$local_binary" \
  --download-url "https://example.invalid/tawny-agent" \
  --sha256 "$sha256" \
  --skip-attestation \
  --dry-run >/dev/null 2>&1; then
  echo "installer accepted conflicting binary sources" >&2
  exit 1
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  # The dry run prints the generated launchd plist; it must lint and carry the
  # hardening keys.
  for scope in system user; do
    scope_args=()
    if [[ "$scope" == "user" ]]; then scope_args=(--user); fi
    plist_out="$test_dir/$scope.plist"
    bash "$installer" ${scope_args[@]+"${scope_args[@]}"} \
      --install-dir "$install_dir" \
      --config-path "$config_path" \
      --state-dir "$state_dir & <odd>" \
      --binary-path "$local_binary" \
      --sha256 "$sha256" \
      --skip-attestation \
      --dry-run | sed -n 's/^\[dry-run\]   //p' > "$plist_out"
    plutil -lint "$plist_out" >/dev/null
    for expected in \
      '"KeepAlive" => true' \
      '"ProcessType" => "Standard"' \
      '"Umask" => 63' \
      '"SessionCreate" => false' \
      '"ThrottleInterval" => 10' \
      "state & <odd>/state.toml"; do
      if ! plutil -p "$plist_out" | grep -F -- "$expected" >/dev/null; then
        echo "$scope plist missing: $expected" >&2
        exit 1
      fi
    done
    if [[ "$scope" == "system" ]]; then
      plutil -p "$plist_out" | grep -F '"StandardErrorPath" => "/Library/Logs/Tawny/agent.log"' >/dev/null
    else
      plutil -p "$plist_out" | grep -F "\"StandardErrorPath\" => \"$HOME/Library/Logs/Tawny/agent.log\"" >/dev/null
    fi
  done
fi

if [[ "$(uname -s)" == "Linux" ]]; then
  # The dry run prints the systemd unit. It must keep User=tawny and every
  # hardening line, and grant exactly the documented capabilities (#59).
  unit_out="$test_dir/tawny-agent.service"
  bash "$installer" \
    --install-dir "$install_dir" \
    --config-path "$config_path" \
    --state-dir "$state_dir" \
    --binary-path "$local_binary" \
    --sha256 "$sha256" \
    --skip-attestation \
    --dry-run | sed -n 's/^\[dry-run\]   //p' > "$unit_out"
  expected_caps="CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_DAC_READ_SEARCH CAP_KILL CAP_SYS_PTRACE"
  for key in AmbientCapabilities CapabilityBoundingSet; do
    lines="$(grep -c "^${key}=" "$unit_out" || true)"
    if [[ "$lines" != "1" ]]; then
      echo "unit has $lines ${key}= lines, want 1" >&2
      exit 1
    fi
    got="$(sed -n "s/^${key}=//p" "$unit_out" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')"
    if [[ "$got" != "$expected_caps" ]]; then
      echo "unit ${key} is '$got', want '$expected_caps'" >&2
      exit 1
    fi
  done
  for expected in \
    'User=tawny' \
    'Group=tawny' \
    'UMask=0027' \
    'NoNewPrivileges=true' \
    'PrivateDevices=true' \
    'PrivateTmp=true' \
    'ProtectClock=true' \
    'ProtectControlGroups=true' \
    'ProtectHome=read-only' \
    'ProtectKernelLogs=true' \
    'ProtectKernelModules=true' \
    'ProtectKernelTunables=true' \
    'ProtectSystem=strict' \
    "ReadWritePaths=\"$state_dir\"" \
    'LockPersonality=true' \
    'MemoryDenyWriteExecute=true' \
    'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
    'RestrictNamespaces=true' \
    'RestrictRealtime=true' \
    'RestrictSUIDSGID=true' \
    'SystemCallArchitectures=native'; do
    if ! grep -Fx -- "$expected" "$unit_out" >/dev/null; then
      echo "unit missing: $expected" >&2
      exit 1
    fi
  done
  if grep -E '^(User|Group)=root|^(PermissionsStartOnly|Privileged)' "$unit_out" >/dev/null; then
    echo "unit runs with root privileges" >&2
    exit 1
  fi
  if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze verify "$unit_out" 2>&1 | grep -iE 'capabilit|unknown (key|lvalue)' && {
      echo "systemd-analyze rejected the capability lines" >&2
      exit 1
    }
  fi
fi

printf 'installer smoke tests passed\n'
