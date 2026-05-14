#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker_dir="$(cd "$script_dir/.." && pwd)"
secrets_dir="$docker_dir/secrets"
env_file="$docker_dir/.env"
jwt_key="$secrets_dir/tawny-jwt-key"

mkdir -p "$secrets_dir"

if [[ ! -f "$jwt_key" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$jwt_key"
  chmod 0600 "$jwt_key"
  echo "created $jwt_key"
else
  echo "kept existing $jwt_key"
fi

touch "$env_file"
chmod 0600 "$env_file"

ensure_env() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "$env_file"; then
    echo "kept existing $key in $env_file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$env_file"
    echo "added $key to $env_file"
  fi
}

ensure_env "TAWNY_WEB_HMAC_SECRET" "$(openssl rand -hex 32)"
ensure_env "BETTER_AUTH_SECRET" "$(openssl rand -hex 32)"
ensure_env "TAWNY_APPLY_MIGRATIONS_ON_STARTUP" "true"
ensure_env "MSSQL_SA_PASSWORD" "DevPassw0rd!"
