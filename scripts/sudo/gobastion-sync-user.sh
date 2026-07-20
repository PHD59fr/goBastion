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

DB_DRIVER_VALUE=""
DB_DSN_VALUE=""
EGRESS_ENC_KEY_VALUE=""
INSTANCE_ID_VALUE=""
while IFS= read -r line || [ -n "$line" ]; do
  key=${line%%=*}
  value=${line#*=}
  case "$key" in
    DB_DRIVER) DB_DRIVER_VALUE=$value ;;
    DB_DSN) DB_DSN_VALUE=$value ;;
    EGRESS_ENC_KEY) EGRESS_ENC_KEY_VALUE=$value ;;
    INSTANCE_ID) INSTANCE_ID_VALUE=$value ;;
  esac
done < /run/gobastion/db.conf

exec /usr/bin/env \
  "DB_DRIVER=$DB_DRIVER_VALUE" "DB_DSN=$DB_DSN_VALUE" \
  "EGRESS_ENC_KEY=$EGRESS_ENC_KEY_VALUE" "INSTANCE_ID=$INSTANCE_ID_VALUE" \
  /app/goBastion --syncUser "$user"
