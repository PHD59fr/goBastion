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

# Never release a managed UID or delete its home before archival identity is
# protected. The authoritative helper reloads the DB under its root lock;
# deleted users become reserved, non-admitted identities. A direct call cannot
# bypass recording revocation through a native deluser operation.
exec /usr/local/sbin/gobastion-sync-user "$user"
