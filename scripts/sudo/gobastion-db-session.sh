#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != root ] || exit 2
DB_DRIVER_VALUE= DB_DSN_VALUE= EGRESS_ENC_KEY_VALUE= INSTANCE_ID_VALUE=
while IFS= read -r line || [ -n "$line" ]; do
 key=${line%%=*};value=${line#*=}
 case "$key" in
 DB_DRIVER) DB_DRIVER_VALUE=$value;; DB_DSN) DB_DSN_VALUE=$value;;
 EGRESS_ENC_KEY) EGRESS_ENC_KEY_VALUE=$value;; INSTANCE_ID) INSTANCE_ID_VALUE=$value;;
 esac
done < /run/gobastion/db.conf
exec /usr/bin/env "DB_DRIVER=$DB_DRIVER_VALUE" "DB_DSN=$DB_DSN_VALUE" "EGRESS_ENC_KEY=$EGRESS_ENC_KEY_VALUE" "INSTANCE_ID=$INSTANCE_ID_VALUE" /app/goBastion --dbSession "$@"
