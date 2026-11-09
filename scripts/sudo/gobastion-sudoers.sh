#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: gobastion-sudoers <username> <admin|remove>" >&2
  exit 2
fi

user=$1
action=$2
if ! printf "%s" "$user" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'; then
  echo "invalid username" >&2
  exit 2
fi

case "$action" in
  admin|remove) ;;
  *)
    echo "invalid action" >&2
    exit 2
    ;;
esac
case "$user" in gobastion|nobody|gobastion-session) echo "reserved account" >&2; exit 2 ;; esac
# The action is a legacy syntax placeholder. Root sync reads fresh DB policy.
exec /usr/local/sbin/gobastion-sync-user "$user"
