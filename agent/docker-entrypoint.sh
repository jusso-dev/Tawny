#!/usr/bin/env sh
set -eu

config_path="${TAWNY_CONFIG:-/etc/tawny/config.toml}"
api_url="${TAWNY_API_URL:-http://api:5080}"
backend_url="${TAWNY_AGENT_BACKEND_URL:-$api_url}"
web_hmac_secret="${TAWNY_WEB_HMAC_SECRET:-}"
web_user_id="${TAWNY_DOCKER_AGENT_WEB_USER_ID:-00000000-0000-0000-0000-000000000000}"
web_user_role="${TAWNY_DOCKER_AGENT_WEB_USER_ROLE:-Admin}"
token_lifetime_hours="${TAWNY_DOCKER_AGENT_TOKEN_LIFETIME_HOURS:-24}"

mkdir -p "$(dirname "$config_path")" /var/lib/tawny

if [ ! -s "$config_path" ] || ! grep -q 'agent_jwt' "$config_path"; then
  if [ -z "$web_hmac_secret" ]; then
    echo "TAWNY_WEB_HMAC_SECRET is required for first-run Docker agent enrollment." >&2
    exit 1
  fi

  ts="$(date +%s)"
  canonical="POST
/api/enrollment-tokens
${ts}
${web_user_id}
${web_user_role}"
  sig="$(printf '%s' "$canonical" | openssl dgst -sha256 -hmac "$web_hmac_secret" -hex | awk '{print $2}')"

  token_response="$(curl -fsS \
    -X POST "${api_url%/}/api/enrollment-tokens" \
    -H "Content-Type: application/json" \
    -H "X-User-Id: $web_user_id" \
    -H "X-User-Role: $web_user_role" \
    -H "X-Timestamp: $ts" \
    -H "X-Signature: $sig" \
    --data "{\"lifetime_hours\":${token_lifetime_hours}}")"
  enrollment_token="$(printf '%s' "$token_response" | jq -r '.token')"

  if [ -z "$enrollment_token" ] || [ "$enrollment_token" = "null" ]; then
    echo "Failed to create Docker agent enrollment token." >&2
    exit 1
  fi

  cat > "$config_path" <<EOF
[backend]
url = "$backend_url"
enrollment_token = "$enrollment_token"

[collection]
heartbeat_interval_seconds = ${TAWNY_AGENT_HEARTBEAT_INTERVAL_SECONDS:-60}
process_interval_seconds = ${TAWNY_AGENT_PROCESS_INTERVAL_SECONDS:-30}
network_interval_seconds = ${TAWNY_AGENT_NETWORK_INTERVAL_SECONDS:-30}
users_interval_seconds = ${TAWNY_AGENT_USERS_INTERVAL_SECONDS:-300}
system_interval_seconds = ${TAWNY_AGENT_SYSTEM_INTERVAL_SECONDS:-3600}
fim_interval_seconds = ${TAWNY_AGENT_FIM_INTERVAL_SECONDS:-300}
max_in_memory_events = ${TAWNY_AGENT_MAX_IN_MEMORY_EVENTS:-1000}
spill_path = "/var/lib/tawny/events.spool"
fim_paths = ${TAWNY_AGENT_FIM_PATHS:-[]}
EOF
fi

exec /usr/local/bin/tawny-agent "$@"
