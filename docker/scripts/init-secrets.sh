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
  echo "created $jwt_key"
else
  echo "kept existing $jwt_key"
fi
# Compose on this engine ignores secret uid/mode. The server runs as uid 65532.
chmod 0644 "$jwt_key"

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

ensure_env "POSTGRES_PASSWORD" "$(openssl rand -hex 24)"
ensure_env "TAWNY_INTEGRATION_ENCRYPTION_KEY" "$(openssl rand -hex 32)"
ensure_env "TAWNY_AGENT_JWT_SEED" "$(openssl rand -hex 32)"
ensure_env "TAWNY_DOMAIN" "localhost"
ensure_env "TAWNY_HTTPS_PORT" "8443"
ensure_env "TAWNY_HTTP_PORT" "8080"
ensure_env "TAWNY_PUBLIC_URL" "https://localhost:8443"
ensure_env "TAWNY_BOOTSTRAP_ADMIN_EMAIL" "admin@tawny.local"
admin_password="$(openssl rand -hex 18)"
if grep -q '^TAWNY_BOOTSTRAP_ADMIN_PASSWORD=' "$env_file"; then
  echo "kept existing TAWNY_BOOTSTRAP_ADMIN_PASSWORD in $env_file"
else
  printf 'TAWNY_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$admin_password" >> "$env_file"
  echo "added TAWNY_BOOTSTRAP_ADMIN_PASSWORD to $env_file"
  echo "bootstrap admin password (printed once): $admin_password"
fi
