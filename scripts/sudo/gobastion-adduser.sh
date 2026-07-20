#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: gobastion-adduser.sh <username>" >&2
  exit 2
fi

user="$1"
if ! printf "%s" "$user" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'; then
  echo "invalid username" >&2
  exit 2
fi

if ! getent passwd "$user" >/dev/null 2>&1; then
  /usr/sbin/adduser --disabled-password --gecos "" "$user"
fi

# All bastion accounts need access to the SQLite database and shared recording
# tree after the main application drops root privileges.
/usr/sbin/addgroup "$user" gobastion
