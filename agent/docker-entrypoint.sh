#!/usr/bin/env sh
set -eu

config_path="${TAWNY_CONFIG:-/etc/tawny/config.toml}"
backend_url="${TAWNY_AGENT_BACKEND_URL:-}"
enrollment_token="${TAWNY_AGENT_ENROLLMENT_TOKEN:-}"

umask 027
mkdir -p "$(dirname "$config_path")" /var/lib/tawny

if [ ! -s "$config_path" ]; then
  if [ -z "$backend_url" ] || [ -z "$enrollment_token" ]; then
    echo "TAWNY_AGENT_BACKEND_URL and TAWNY_AGENT_ENROLLMENT_TOKEN are required on first start." >&2
    exit 1
  fi
  case "$backend_url" in
    https://*) ;;
    *)
      if [ "${TAWNY_AGENT_ALLOW_INSECURE_HTTP:-false}" != "true" ]; then
        echo "TAWNY_AGENT_BACKEND_URL must use HTTPS." >&2
        exit 1
      fi
      ;;
  esac
  sanitized_backend="$(printf '%s' "$backend_url" | tr -d '\r\n')"
  sanitized_token="$(printf '%s' "$enrollment_token" | tr -d '\r\n')"
  if [ "$sanitized_backend" != "$backend_url" ] || [ "$sanitized_token" != "$enrollment_token" ]; then
    echo "Backend URL and enrollment token must be single-line values." >&2
    exit 1
  fi
  escaped_backend="$(printf '%s' "$backend_url" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  escaped_token="$(printf '%s' "$enrollment_token" | sed 's/\\/\\\\/g; s/"/\\"/g')"

  cat > "$config_path" <<EOF
[backend]
url = "$escaped_backend"
enrollment_token = "$escaped_token"

[collection]
heartbeat_interval_seconds = ${TAWNY_AGENT_HEARTBEAT_INTERVAL_SECONDS:-60}
process_interval_seconds = ${TAWNY_AGENT_PROCESS_INTERVAL_SECONDS:-30}
process_events_interval_seconds = ${TAWNY_AGENT_PROCESS_EVENTS_INTERVAL_SECONDS:-5}
network_interval_seconds = ${TAWNY_AGENT_NETWORK_INTERVAL_SECONDS:-30}
users_interval_seconds = ${TAWNY_AGENT_USERS_INTERVAL_SECONDS:-300}
system_interval_seconds = ${TAWNY_AGENT_SYSTEM_INTERVAL_SECONDS:-3600}
fim_interval_seconds = ${TAWNY_AGENT_FIM_INTERVAL_SECONDS:-300}
fs_events_interval_seconds = ${TAWNY_AGENT_FS_EVENTS_INTERVAL_SECONDS:-5}
dns_interval_seconds = ${TAWNY_AGENT_DNS_INTERVAL_SECONDS:-30}
supply_chain_interval_seconds = ${TAWNY_AGENT_SUPPLY_CHAIN_INTERVAL_SECONDS:-21600}
max_in_memory_events = ${TAWNY_AGENT_MAX_IN_MEMORY_EVENTS:-1000}
max_spool_bytes = ${TAWNY_AGENT_MAX_SPOOL_BYTES:-268435456}
http_timeout_seconds = ${TAWNY_AGENT_HTTP_TIMEOUT_SECONDS:-30}
max_retry_backoff_seconds = ${TAWNY_AGENT_MAX_RETRY_BACKOFF_SECONDS:-300}
spill_path = "/var/lib/tawny/events.spool"
fim_paths = ${TAWNY_AGENT_FIM_PATHS:-[]}
EOF
  chmod 0600 "$config_path"
fi

exec /usr/local/bin/tawny-agent "$@"
