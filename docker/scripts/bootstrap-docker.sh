#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker_dir="$(cd "$script_dir/.." && pwd)"
repo_dir="$(cd "$docker_dir/.." && pwd)"
env_file="$docker_dir/.env"
project_name="${TAWNY_DOCKER_PROJECT:-tawny}"
platform="${DOCKER_DEFAULT_PLATFORM:-}"
admin_email="${TAWNY_BOOTSTRAP_ADMIN_EMAIL:-}"
admin_password="${TAWNY_BOOTSTRAP_ADMIN_PASSWORD:-}"
build_arg="--build"
with_agent="false"

usage() {
  cat <<'EOF'
Usage: docker/scripts/bootstrap-docker.sh [options]

Bootstraps Tawny in Docker:
  - creates local secrets and docker/.env
  - starts PostgreSQL, tawny-server, and Caddy (Caddy terminates TLS)
  - tawny-server applies migrations and creates the first admin only when no users exist
  - verifies https://localhost:<port>/api/health

Options:
  --admin-email EMAIL       Bootstrap admin email, used only when no users exist
  --admin-password PASS     Bootstrap admin password, used only when no users exist
  --project-name NAME       Docker Compose project. Default: tawny
  --platform PLATFORM       Docker platform, e.g. linux/arm64
  --no-build                Do not rebuild the tawny-server image
  --with-agent              Start the optional Linux agent profile (needs TAWNY_AGENT_ENROLLMENT_TOKEN)
  --with-synthetic-agent    Alias for --with-agent
  --with-docker-agent       Alias for --with-agent
  -h, --help                Show this help

Examples:
  docker/scripts/bootstrap-docker.sh
  TAWNY_BOOTSTRAP_ADMIN_PASSWORD='better-local-password' docker/scripts/bootstrap-docker.sh
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-email)
      admin_email="${2:?--admin-email requires a value}"
      shift 2
      ;;
    --admin-password)
      admin_password="${2:?--admin-password requires a value}"
      shift 2
      ;;
    --project-name)
      project_name="${2:?--project-name requires a value}"
      shift 2
      ;;
    --platform)
      platform="${2:?--platform requires a value}"
      shift 2
      ;;
    --no-build)
      build_arg=""
      shift
      ;;
    --with-agent|--with-synthetic-agent|--with-docker-agent)
      with_agent="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

log() {
  printf '\n==> %s\n' "$1"
}

ensure_env() {
  local key="$1"
  local value="$2"

  touch "$env_file"
  if grep -q "^${key}=" "$env_file"; then
    return
  fi

  printf '%s=%s\n' "$key" "$value" >> "$env_file"
}

set_env() {
  local key="$1"
  local value="$2"
  local tmp_file

  touch "$env_file"
  tmp_file="$(mktemp)"
  grep -v "^${key}=" "$env_file" > "$tmp_file" || true
  printf '%s=%s\n' "$key" "$value" >> "$tmp_file"
  mv "$tmp_file" "$env_file"
}

read_env_value() {
  local key="$1"
  local value

  value="$(grep -E "^${key}=" "$env_file" | tail -n 1 | cut -d '=' -f 2- || true)"
  printf '%s' "$value"
}

port_in_use() {
  local port="$1"

  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return
  fi

  if command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "$port" >/dev/null 2>&1
    return
  fi

  return 1
}

port_owned_by_tawny() {
  local port="$1"

  docker ps --filter 'name=^/tawny-' --format '{{.Ports}}' 2>/dev/null | grep -q ":${port}->"
}

choose_port() {
  local preferred="$1"
  local port="$preferred"

  while port_in_use "$port" && ! port_owned_by_tawny "$port"; do
    port=$((port + 1))
  done

  printf '%s' "$port"
}

ensure_port_env() {
  local key="$1"
  local preferred="$2"
  local configured
  local selected

  configured="$(read_env_value "$key")"
  if [[ -n "$configured" ]]; then
    printf '%s' "$configured"
    return
  fi

  selected="$(choose_port "$preferred")"
  set_env "$key" "$selected"
  if [[ "$selected" != "$preferred" ]]; then
    echo "Port $preferred is in use; using $selected for $key" >&2
  fi
  printf '%s' "$selected"
}

wait_for_url() {
  local url="$1"
  local label="$2"
  local timeout_seconds="${3:-180}"
  local started
  started="$(date +%s)"

  printf 'Waiting for %s at %s' "$label" "$url"
  while true; do
    if curl -kfsS "$url" >/dev/null 2>&1; then
      printf '\n'
      return
    fi

    if (( "$(date +%s)" - started >= timeout_seconds )); then
      printf '\n'
      echo "Timed out waiting for $label. Recent logs:" >&2
      docker compose -p "$project_name" -f "$docker_dir/docker-compose.yml" logs --tail=80 tawny-server caddy postgres >&2 || true
      exit 1
    fi

    printf '.'
    sleep 2
  done
}

compose() {
  docker compose -p "$project_name" --env-file "$env_file" -f "$docker_dir/docker-compose.yml" "$@"
}

compose_agent() {
  docker compose -p "$project_name" --env-file "$env_file" -f "$docker_dir/docker-compose.yml" --profile agent "$@"
}

create_agent_token() {
  local hmac_secret
  local timestamp
  local canonical
  local signature
  local response
  local token

  hmac_secret="$(read_env_value TAWNY_WEB_HMAC_SECRET)"
  timestamp="$(date +%s)"
  nonce="$(openssl rand -hex 16)"
  body='{"lifetime_hours":24}'
  body_hash="$(printf '%s' "$body" | openssl dgst -sha256 | awk '{print $2}')"
  tenant_id="00000000-0000-0000-0000-000000000001"
  user_id="00000000-0000-0000-0000-000000000000"
  role="Admin"
  content_type="application/json"
  canonical="$(printf 'v2\nPOST\n/api/enrollment-tokens\n\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$body_hash" "$content_type" "$user_id" "$role" "$tenant_id" "$timestamp" "$nonce")"
  signature="$(printf '%s' "$canonical" | openssl dgst -sha256 -hmac "$hmac_secret" | awk '{print $2}')"
  response="$(curl -fsS \
    -H 'Content-Type: application/json' \
    -H "X-User-Id: $user_id" \
    -H "X-User-Role: $role" \
    -H "X-Tenant-Id: $tenant_id" \
    -H "X-Timestamp: $timestamp" \
    -H "X-Nonce: $nonce" \
    -H "X-Signature: $signature" \
    --data "$body" \
    "http://localhost:${api_port}/api/enrollment-tokens")"
  token="$(printf '%s' "$response" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  if [[ -z "$token" ]]; then
    echo "Could not parse enrollment token from API response: $response" >&2
    exit 1
  fi
  printf '%s' "$token"
}

need_command docker
need_command openssl
need_command curl

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required. Install Docker Desktop or the docker compose plugin." >&2
  exit 1
fi

log "Creating local secrets"
if [[ -n "$admin_email" ]]; then
  set_env "TAWNY_BOOTSTRAP_ADMIN_EMAIL" "$admin_email"
fi
if [[ -n "$admin_password" ]]; then
  set_env "TAWNY_BOOTSTRAP_ADMIN_PASSWORD" "$admin_password"
fi
"$script_dir/init-secrets.sh"

https_port="$(ensure_port_env TAWNY_HTTPS_PORT 8443)"
admin_email="$(read_env_value TAWNY_BOOTSTRAP_ADMIN_EMAIL)"

if [[ -n "$platform" ]]; then
  export DOCKER_DEFAULT_PLATFORM="$platform"
fi

log "Starting PostgreSQL, tawny-server, and Caddy"
if [[ -n "$build_arg" ]]; then
  compose up -d "$build_arg"
else
  compose up -d
fi
compose up -d --wait postgres tawny-server caddy

log "Verifying HTTPS health"
wait_for_url "https://localhost:${https_port}/api/health" "tawny-server health"

if [[ "$with_agent" == "true" ]]; then
  token="$(read_env_value TAWNY_AGENT_ENROLLMENT_TOKEN)"
  if [[ -z "$token" ]]; then
    echo "TAWNY_AGENT_ENROLLMENT_TOKEN is empty. Create one in Enrollment, put it in docker/.env, then rerun with --with-agent." >&2
    exit 1
  fi
  log "Starting real Linux agent container"
  compose_agent up -d --build agent
fi

cat <<EOF

Tawny is running.

Dashboard: https://localhost:${https_port}
Health:    https://localhost:${https_port}/api/health
Postgres is only on the compose network.

Admin email: $admin_email
The bootstrap password is in docker/.env. init-secrets prints it once, when it is first generated. The server uses it only when the user table is empty, and it does not log the password.

Useful commands:
  cd "$docker_dir" && docker compose -p "$project_name" logs -f tawny-server caddy postgres
  cd "$docker_dir" && docker compose -p "$project_name" --profile agent logs -f agent
  cd "$docker_dir" && docker compose -p "$project_name" down
EOF
