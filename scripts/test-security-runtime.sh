#!/bin/sh
# Run only inside a disposable image, with no host volumes:
# docker run --rm --entrypoint /bin/sh -i gobastion-test < scripts/test-security-runtime.sh
set -eu
step=initialization
trap 'status=$?; if [ "$status" -ne 0 ]; then echo "FAIL: $step" >&2; for log in /tmp/bootstrap.out /tmp/create.out /tmp/modify.out /tmp/expire.out; do if [ -f "$log" ]; then cat "$log" >&2; fi; done; fi' EXIT

test -f /.dockerenv
test -x /app/goBastion
# Disposable test-only key; production must inject and preserve its own key.
EGRESS_ENC_KEY=$(head -c 32 /dev/urandom | base64)
export EGRESS_ENC_KEY
test ! -e /var/lib/goBastion/bastion.db
umask 0007
mkdir -p /run/gobastion
chmod 0700 /run/gobastion
: > /run/gobastion/db.conf
chmod 0600 /run/gobastion/db.conf

ssh-keygen -q -t ed25519 -N '' -f /tmp/security-ingress
public_key=$(cat /tmp/security-ingress.pub)
step=bootstrap
printf 'admin\n%s\n' "$public_key" | /app/goBastion --firstInstall > /tmp/bootstrap.out
grep -q 'created successfully as administrator' /tmp/bootstrap.out

as_admin() {
  su-exec admin env HOME=/home/admin /app/goBastion "$@"
}

step=account-creation
printf '%s\n' "$public_key" | as_admin '-osh accountCreate --user target' > /tmp/create.out
grep -q 'created successfully' /tmp/create.out
as_admin '-osh accountModify --user target --sysrole admin' > /tmp/modify.out
grep -q 'system role: admin' /tmp/modify.out
test -s /etc/sudoers.d/target
test -s /home/target/.ssh/authorized_keys

# Refuse self-deletion even when another administrator exists.
as_admin '-osh accountDelete --user admin' > /tmp/delete.out
grep -q 'cannot delete your own account' /tmp/delete.out
getent passwd admin > /dev/null

# Revoke an established target process, keys and delegation at the next sync.
step=session-revocation
su-exec target sleep 600 &
target_pid=$!
as_admin '-osh accountExpire --user target' > /tmp/expire.out
grep -q 'locked immediately' /tmp/expire.out
/app/goBastion --sync
if kill -0 "$target_pid" 2>/dev/null; then
  echo 'disabled account process survived sync' >&2
  exit 1
fi
wait "$target_pid" 2>/dev/null || true
test ! -e /etc/sudoers.d/target
test ! -s /home/target/.ssh/authorized_keys
echo 'PASS: disabled account sessions, ingress keys and sudo delegation revoked'

# BusyBox pgrep exit 1 means no matching processes; exit 0 means keep the user.
step=orphan-cleanup
/usr/local/sbin/gobastion-adduser orphan
/usr/local/sbin/gobastion-adduser activeorphan
su-exec activeorphan sleep 600 &
active_pid=$!
/app/goBastion --sync
if getent passwd orphan > /dev/null; then
  echo 'idle orphan account survived sync' >&2
  exit 1
fi
getent passwd activeorphan > /dev/null
kill -0 "$active_pid"
kill "$active_pid"
wait "$active_pid" 2>/dev/null || true
echo 'PASS: BusyBox process detection removes idle orphan and preserves active account'

# Account-only mode must reject every interactive entry point without a PTY.
step=interactive-restrictions
as_admin '-osh accountModify --user admin --oshOnly true' > /tmp/osh.out
as_admin '--' > /tmp/interactive.out
grep -q 'Interactive mode is disabled' /tmp/interactive.out
as_admin '-osh' > /tmp/empty-osh.out
grep -q 'Usage:' /tmp/empty-osh.out
echo 'PASS: restricted interactive entry points denied'
