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

entry=$(getent passwd "$user" 2>/dev/null) || { echo "unknown user" >&2; exit 2; }
uid=$(printf '%s' "$entry" | cut -d: -f3)
if [ "$uid" -lt 1000 ]; then
  echo "refusing to manage system account" >&2
  exit 2
fi

# Never leave an administrator delegation behind: recreating the same login
# must not inherit privileges from the deleted account.
rm -f "/etc/sudoers.d/$user"
exec /usr/sbin/deluser --remove-home "$user"
