#!/bin/sh
set -eu
umask 0007

if [ "$#" -ne 1 ]; then
  echo "usage: gobastion-sync-user <username>" >&2
  exit 2
fi

user=$1
if ! printf "%s" "$user" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'; then
  echo "invalid username" >&2
  exit 2
fi

case "$user" in gobastion|nobody|gobastion-session) echo "refusing to manage reserved account" >&2; exit 2 ;; esac

if entry=$(getent passwd "$user" 2>/dev/null); then
  uid=$(printf '%s' "$entry" | cut -d: -f3)
  case "$uid" in ''|*[!0-9]*) echo "invalid user ID" >&2; exit 2 ;; esac
  if [ "${#uid}" -gt 5 ]; then
    echo "invalid user ID" >&2
    exit 2
  fi
  if [ "$uid" -lt 1000 ] || [ "$uid" -ge 65000 ]; then
    echo "refusing to manage system account" >&2
    exit 2
  fi
else
  status=$?
  if [ "$status" -ne 2 ]; then
    echo "user lookup failed" >&2
    exit 2
  fi
fi

DB_DRIVER_VALUE=""
DB_DSN_VALUE=""
EGRESS_ENC_KEY_VALUE=""
EGRESS_ENC_KEY_ID_VALUE="default"
EGRESS_ENC_KEYS_VALUE="{}"
INSTANCE_ID_VALUE=""
OBS_ENABLED_VALUE=false
OTEL_SDK_DISABLED_VALUE=""
OTEL_TRACES_EXPORTER_VALUE=""
OTEL_EXPORTER_OTLP_ENDPOINT_VALUE=""
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_VALUE=""
OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK_VALUE=""
OTEL_SERVICE_NAME_VALUE=""
while IFS= read -r line || [ -n "$line" ]; do
  key=${line%%=*}
  value=${line#*=}
  case "$key" in
    DB_DRIVER) DB_DRIVER_VALUE=$value ;;
    DB_DSN) DB_DSN_VALUE=$value ;;
    EGRESS_ENC_KEY) EGRESS_ENC_KEY_VALUE=$value ;;
    EGRESS_ENC_KEY_ID) EGRESS_ENC_KEY_ID_VALUE=$value ;;
    EGRESS_ENC_KEYS) EGRESS_ENC_KEYS_VALUE=$value ;;
    INSTANCE_ID) INSTANCE_ID_VALUE=$value ;;
    OBS_ENABLED) OBS_ENABLED_VALUE=$value ;;
    OTEL_SDK_DISABLED) OTEL_SDK_DISABLED_VALUE=$value ;;
    OTEL_TRACES_EXPORTER) OTEL_TRACES_EXPORTER_VALUE=$value ;;
    OTEL_EXPORTER_OTLP_ENDPOINT) OTEL_EXPORTER_OTLP_ENDPOINT_VALUE=$value ;;
    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_VALUE=$value ;;
    OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK) OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK_VALUE=$value ;;
    OTEL_SERVICE_NAME) OTEL_SERVICE_NAME_VALUE=$value ;;
  esac
done < /run/gobastion/db.conf

unset SSH_CLIENT SSH_CONNECTION SSH_TTY TMPDIR TMP TEMP

exec /usr/bin/env \
  "DB_DRIVER=$DB_DRIVER_VALUE" "DB_DSN=$DB_DSN_VALUE" \
  "EGRESS_ENC_KEY=$EGRESS_ENC_KEY_VALUE" "EGRESS_ENC_KEY_ID=$EGRESS_ENC_KEY_ID_VALUE" \
    "EGRESS_ENC_KEYS=$EGRESS_ENC_KEYS_VALUE" "INSTANCE_ID=$INSTANCE_ID_VALUE" "OBS_ENABLED=$OBS_ENABLED_VALUE" \
    "OTEL_SDK_DISABLED=$OTEL_SDK_DISABLED_VALUE" "OTEL_TRACES_EXPORTER=$OTEL_TRACES_EXPORTER_VALUE" \
    "OTEL_EXPORTER_OTLP_ENDPOINT=$OTEL_EXPORTER_OTLP_ENDPOINT_VALUE" \
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=$OTEL_EXPORTER_OTLP_TRACES_ENDPOINT_VALUE" \
    "OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK=$OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK_VALUE" \
    "OTEL_SERVICE_NAME=$OTEL_SERVICE_NAME_VALUE" \
  /app/goBastion --syncUser "$user"
