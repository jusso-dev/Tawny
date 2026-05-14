#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker_dir="$(cd "$script_dir/.." && pwd)"
repo_dir="$(cd "$docker_dir/.." && pwd)"
env_file="$docker_dir/.env"
project_name="${TAWNY_DOCKER_PROJECT:-tawny}"
platform="${DOCKER_DEFAULT_PLATFORM:-}"
admin_email="${BOOTSTRAP_ADMIN_EMAIL:-admin@example.com}"
admin_password="${BOOTSTRAP_ADMIN_PASSWORD:-ChangeMe123!}"
admin_name="${BOOTSTRAP_ADMIN_NAME:-Tawny Admin}"
build_arg="--build"
with_synthetic_agent="false"

usage() {
  cat <<'EOF'
Usage: docker/scripts/bootstrap-docker.sh [options]

Bootstraps Tawny in Docker:
  - creates local secrets and docker/.env
  - starts SQL Server, the .NET API, and the Next.js web app
  - runs the web Prisma migration
  - creates the first admin user if no users exist
  - verifies the API and web endpoints

Options:
  --admin-email EMAIL       Admin email. Default: admin@example.com
  --admin-password PASS     Admin password. Default: ChangeMe123!
  --admin-name NAME         Admin display name. Default: Tawny Admin
  --project-name NAME       Docker Compose project. Default: tawny
  --platform PLATFORM       Docker platform, e.g. linux/amd64 for Apple Silicon SQL Server
  --no-build                Do not rebuild api/web images
  --with-synthetic-agent    Start the Docker synthetic telemetry agent after bootstrap
  -h, --help                Show this help

Examples:
  docker/scripts/bootstrap-docker.sh
  docker/scripts/bootstrap-docker.sh --platform linux/amd64
  BOOTSTRAP_ADMIN_PASSWORD='better-local-password' docker/scripts/bootstrap-docker.sh
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
    --admin-name)
      admin_name="${2:?--admin-name requires a value}"
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
    --with-synthetic-agent)
      with_synthetic_agent="true"
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
    if curl -fsS "$url" >/dev/null 2>&1; then
      printf '\n'
      return
    fi

    if (( "$(date +%s)" - started >= timeout_seconds )); then
      printf '\n'
      echo "Timed out waiting for $label. Recent logs:" >&2
      docker compose -p "$project_name" -f "$docker_dir/docker-compose.yml" logs --tail=80 api web db >&2 || true
      exit 1
    fi

    printf '.'
    sleep 2
  done
}

compose() {
  docker compose -p "$project_name" --env-file "$env_file" -f "$docker_dir/docker-compose.yml" "$@"
}

compose_telemetry() {
  docker compose -p "$project_name" --env-file "$env_file" -f "$docker_dir/docker-compose.yml" --profile telemetry "$@"
}

need_command docker
need_command openssl
need_command curl

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required. Install Docker Desktop or the docker compose plugin." >&2
  exit 1
fi

log "Creating local secrets"
"$script_dir/init-secrets.sh"
ensure_env "MSSQL_SA_PASSWORD" "DevPassw0rd!"

mssql_password="$(read_env_value MSSQL_SA_PASSWORD)"
if [[ -z "$mssql_password" ]]; then
  echo "MSSQL_SA_PASSWORD is missing from $env_file" >&2
  exit 1
fi

mssql_port="$(ensure_port_env MSSQL_PORT 1433)"
api_port="$(ensure_port_env TAWNY_API_PORT 5080)"
web_port="$(ensure_port_env TAWNY_WEB_PORT 3000)"

if [[ -n "$platform" ]]; then
  export DOCKER_DEFAULT_PLATFORM="$platform"
fi

log "Starting Tawny Docker services"
if [[ -n "$build_arg" ]]; then
  compose up -d "$build_arg"
else
  compose up -d
fi

log "Waiting for SQL Server"
compose up -d --wait db

log "Running web database migration and admin seed"
docker run --rm \
  --network "${project_name}_default" \
  -v "$repo_dir/web:/app" \
  -v "${project_name}-web-node-modules:/app/node_modules" \
  -v "${project_name}-pnpm-store:/pnpm/store" \
  -w /app \
  -e "PNPM_HOME=/pnpm" \
  -e "DATABASE_URL=sqlserver://db:1433;database=Tawny;user=sa;password=${mssql_password};encrypt=false;trustServerCertificate=true" \
  -e "BOOTSTRAP_ADMIN_EMAIL=$admin_email" \
  -e "BOOTSTRAP_ADMIN_PASSWORD=$admin_password" \
  -e "BOOTSTRAP_ADMIN_NAME=$admin_name" \
  node:22-bookworm \
  bash -lc 'corepack enable && pnpm config set store-dir /pnpm/store && pnpm install --frozen-lockfile && pnpm exec prisma generate && (pnpm db:migrate || (pnpm exec prisma db execute --schema prisma/schema.prisma --file prisma/migrations/20260514005000_better_auth_init/migration.sql && pnpm exec prisma migrate resolve --applied 20260514005000_better_auth_init)) && pnpm seed'

log "Verifying HTTP endpoints"
wait_for_url "http://localhost:${api_port}/api/health" "API health"
wait_for_url "http://localhost:${web_port}" "web app"

if [[ "$with_synthetic_agent" == "true" ]]; then
  log "Starting synthetic telemetry agent"
  compose_telemetry up -d synthetic-agent
fi

cat <<EOF

Tawny is running.

Web:  http://localhost:$web_port
API:  http://localhost:$api_port
SQL:  localhost:$mssql_port

Admin login:
  Email:    $admin_email
  Password: $admin_password

Useful commands:
  cd "$docker_dir" && docker compose -p "$project_name" logs -f api web db
  cd "$docker_dir" && docker compose -p "$project_name" --profile telemetry logs -f synthetic-agent
  cd "$docker_dir" && docker compose -p "$project_name" down
EOF
