#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: gobastion-deluser.sh <username>" >&2
  exit 2
fi

user="$1"
if ! printf "%s" "$user" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'; then
  echo "invalid username" >&2
  exit 2
fi

exec /usr/sbin/deluser --remove-home "$user"
