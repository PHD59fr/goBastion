#!/bin/sh
set -eu
umask 0077

original_command=${1:-}
if [ "$#" -gt 1 ] || [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = "root" ]; then
  echo "gobastion-session must be invoked by sshd through sudo" >&2
  exit 2
fi

# Database requests already have a root supervisor that authenticates SUDO_USER,
# applies policy and MFA, and starts only fixed clients in NsJail. Dispatch them
# before giving an unprivileged session process the control-plane bootstrap.
# Disable pathname expansion: the supervisor, not the shell, validates argv.
case "$original_command" in
  --db|-db|--db\ *|-db\ *)
    set -f
    set -- $original_command
    shift
    exec /usr/local/sbin/gobastion-db-session "$@"
    ;;
esac

# G1: pass bootstrap secrets to goBastion via an inherited, unlinked fd rather
# than the process's initial environment, so secrets do not appear in
# /proc/<pid>/environ. The child reads fd 3 once during bootstrap.
bs_file=$(mktemp /run/gobastion/bootstrap.XXXXXXXXXX)
trap 'rm -f "$bs_file"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cat /run/gobastion/db.conf > "$bs_file"
exec 3< "$bs_file"
rm -f "$bs_file"
trap - EXIT HUP INT TERM

# Preserve SSH/session context vars needed by goBastion; exclude bootstrap secrets
# and unrelated root/sudo environment.
set -- \
  "HOME=/home/$SUDO_USER" "USER=$SUDO_USER" "LOGNAME=$SUDO_USER" \
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
[ -n "${TERM:-}" ] && set -- "$@" "TERM=$TERM"
[ -n "${SSH_CLIENT:-}" ] && set -- "$@" "SSH_CLIENT=$SSH_CLIENT"
[ -n "${SSH_CONNECTION:-}" ] && set -- "$@" "SSH_CONNECTION=$SSH_CONNECTION"
[ -n "${SSH_TTY:-}" ] && set -- "$@" "SSH_TTY=$SSH_TTY"

if [ -n "$original_command" ]; then
  exec /sbin/su-exec "$SUDO_USER" /usr/bin/env -i "$@" \
    /app/goBastion --bootstrap-fd=3 "$original_command"
fi

exec /sbin/su-exec "$SUDO_USER" /usr/bin/env -i "$@" \
  /app/goBastion --bootstrap-fd=3
