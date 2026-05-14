#!/usr/bin/env sh
set -eu

config_path="${TAWNY_CONFIG:-/etc/tawny/config.toml}"
backend_url="${TAWNY_AGENT_BACKEND_URL:-http://api:5080}"
enrollment_token="${TAWNY_AGENT_ENROLLMENT_TOKEN:-}"
fim_paths="${TAWNY_AGENT_FIM_PATHS:-/etc/hosts,/var/lib/tawny/watch.txt}"

heartbeat_interval="${TAWNY_AGENT_HEARTBEAT_INTERVAL_SECONDS:-15}"
process_interval="${TAWNY_AGENT_PROCESS_INTERVAL_SECONDS:-15}"
network_interval="${TAWNY_AGENT_NETWORK_INTERVAL_SECONDS:-15}"
users_interval="${TAWNY_AGENT_USERS_INTERVAL_SECONDS:-60}"
system_interval="${TAWNY_AGENT_SYSTEM_INTERVAL_SECONDS:-60}"
fim_interval="${TAWNY_AGENT_FIM_INTERVAL_SECONDS:-30}"

mkdir -p "$(dirname "$config_path")" /var/lib/tawny
touch /var/lib/tawny/watch.txt

if ! grep -q '^agent_jwt = ' "$config_path" 2>/dev/null; then
  if [ -z "$enrollment_token" ]; then
    echo "TAWNY_AGENT_ENROLLMENT_TOKEN is required for first container start." >&2
    echo "Create one in Tawny Enrollment, set it in docker/.env, then restart tawny-agent-linux." >&2
    exit 1
  fi

  {
    printf '[backend]\n'
    printf 'url = "%s"\n' "$backend_url"
    printf 'enrollment_token = "%s"\n\n' "$enrollment_token"
    printf '[collection]\n'
    printf 'heartbeat_interval_seconds = %s\n' "$heartbeat_interval"
    printf 'process_interval_seconds = %s\n' "$process_interval"
    printf 'network_interval_seconds = %s\n' "$network_interval"
    printf 'users_interval_seconds = %s\n' "$users_interval"
    printf 'system_interval_seconds = %s\n' "$system_interval"
    printf 'fim_interval_seconds = %s\n' "$fim_interval"
    printf 'max_in_memory_events = 1000\n'
    printf 'spill_path = "/etc/tawny/events.spool"\n'
    printf 'fim_paths = ['
    first="true"
    old_ifs="$IFS"
    IFS=","
    for path in $fim_paths; do
      IFS="$old_ifs"
      if [ "$first" = "true" ]; then
        first="false"
      else
        printf ', '
      fi
      escaped="$(printf '%s' "$path" | sed 's/\\/\\\\/g; s/"/\\"/g')"
      printf '"%s"' "$escaped"
      IFS=","
    done
    IFS="$old_ifs"
    printf ']\n'
  } > "$config_path"
fi

exec /usr/local/bin/tawny-agent
