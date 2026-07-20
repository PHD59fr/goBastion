#!/bin/sh
set -eu
umask 0007

if [ "$#" -gt 1 ] || [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = "root" ]; then
  echo "gobastion-session must be invoked by sshd through sudo" >&2
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

original_command=${1:-}
if [ -n "$original_command" ]; then
  exec /sbin/su-exec "$SUDO_USER" /usr/bin/env \
    "HOME=/home/$SUDO_USER" "USER=$SUDO_USER" "LOGNAME=$SUDO_USER" \
    "DB_DRIVER=$DB_DRIVER_VALUE" "DB_DSN=$DB_DSN_VALUE" \
    "EGRESS_ENC_KEY=$EGRESS_ENC_KEY_VALUE" "INSTANCE_ID=$INSTANCE_ID_VALUE" \
    /app/goBastion "$original_command"
fi

exec /sbin/su-exec "$SUDO_USER" /usr/bin/env \
  "HOME=/home/$SUDO_USER" "USER=$SUDO_USER" "LOGNAME=$SUDO_USER" \
  "DB_DRIVER=$DB_DRIVER_VALUE" "DB_DSN=$DB_DSN_VALUE" \
  "EGRESS_ENC_KEY=$EGRESS_ENC_KEY_VALUE" "INSTANCE_ID=$INSTANCE_ID_VALUE" \
  /app/goBastion
