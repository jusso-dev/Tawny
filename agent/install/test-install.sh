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

printf 'installer smoke tests passed\n'
