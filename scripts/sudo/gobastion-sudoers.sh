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

target="/etc/sudoers.d/$user"
case "$action" in
  admin)
    umask 077
    tmp=$(mktemp "/etc/sudoers.d/.gobastion-$user.XXXXXX")
    trap 'rm -f "$tmp"' EXIT HUP INT TERM
    {
      printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-adduser *\n' "$user"
      printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-passwd-delete *\n' "$user"
      printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-deluser *\n' "$user"
      printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-chown-ssh *\n' "$user"
      printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-sudoers *\n' "$user"
    } > "$tmp"
    chmod 0440 "$tmp"
    if command -v visudo >/dev/null 2>&1; then
      visudo -cf "$tmp" >/dev/null
    fi
    mv "$tmp" "$target"
    trap - EXIT HUP INT TERM
    ;;
  remove)
    rm -f "$target"
    ;;
  *)
    echo "invalid action" >&2
    exit 2
    ;;
esac
