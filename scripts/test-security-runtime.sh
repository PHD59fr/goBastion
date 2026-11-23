#!/bin/sh
# Run only inside a fresh disposable image, with no persistent host volumes:
# docker run --rm --entrypoint /bin/sh -i gobastion-test < scripts/test-security-runtime.sh
set -eu

# Refuse an existing installation before changing configuration or OS state.
test -f /.dockerenv
test "$(id -u)" -eq 0
test -x /app/goBastion
test -x /app/audit-writer
test ! -e /var/lib/goBastion/bastion.db
test ! -e /var/lib/goBastion/bastion.db-wal
test ! -e /var/lib/goBastion/bastion.db-shm
test ! -e /run/gobastion/db.conf
test ! -e /run/gobastion-audit/audit.sock
test -s /etc/sudoers.d/gobastion-session

step=initialization
test_dir=$(mktemp -d /tmp/gobastion-security-runtime.XXXXXX)
audit_pid=
target_pid=
finish() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ]; then
    echo "FAIL: $step" >&2
    for log in "$test_dir"/*.out; do
      [ ! -f "$log" ] || cat "$log" >&2
    done
  fi
  [ -z "$target_pid" ] || kill "$target_pid" 2>/dev/null || true
  [ -z "$target_pid" ] || wait "$target_pid" 2>/dev/null || true
  [ -z "$audit_pid" ] || kill -TERM "$audit_pid" 2>/dev/null || true
  [ -z "$audit_pid" ] || wait "$audit_pid" 2>/dev/null || true
  rm -rf "$test_dir"
  exit "$status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# This key belongs only to this disposable fixture. The privileged helpers
# reload the same root-only bootstrap file as the production wrappers.
umask 0077
EGRESS_ENC_KEY=$(head -c 32 /dev/urandom | base64)
DB_DRIVER=sqlite
DB_DSN=/var/lib/goBastion/bastion.db
INSTANCE_ID=security-runtime-test
export EGRESS_ENC_KEY DB_DRIVER DB_DSN INSTANCE_ID
mkdir -p /run/gobastion
chmod 0700 /run/gobastion
printf 'DB_DRIVER=%s\nDB_DSN=%s\nINSTANCE_ID=%s\nEGRESS_ENC_KEY=%s\n' \
  "$DB_DRIVER" "$DB_DSN" "$INSTANCE_ID" "$EGRESS_ENC_KEY" > /run/gobastion/db.conf
chmod 0600 /run/gobastion/db.conf
sudo_policy=$(sha256sum /etc/sudoers.d/gobastion-session)

step=audit-startup
/app/audit-writer > "$test_dir/audit.out" 2>&1 &
audit_pid=$!
attempt=0
while [ ! -S /run/gobastion-audit/audit.sock ]; do
  kill -0 "$audit_pid"
  attempt=$((attempt + 1))
  [ "$attempt" -lt 50 ] || { echo 'audit collector did not start' >&2; exit 1; }
  sleep 0.1
done

ssh-keygen -q -t ed25519 -N '' -f "$test_dir/ingress"
public_key=$(cat "$test_dir/ingress.pub")
step=bootstrap
printf 'admin\n%s\n' "$public_key" | timeout 30 /app/goBastion --firstInstall > "$test_dir/bootstrap.out" 2>&1
grep -q 'created successfully as administrator' "$test_dir/bootstrap.out"

# Exercise the sudo/ForceCommand wrapper and inherited bootstrap descriptor.
# The caller has no encryption keys or database DSN in its environment.
as_admin() {
  timeout 30 su-exec admin env -i \
    HOME=/home/admin USER=admin LOGNAME=admin \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SSH_CONNECTION='127.0.0.1 40000 127.0.0.1 22' SSH_CLIENT='127.0.0.1 40000 22' \
    /usr/bin/sudo -n /usr/local/sbin/gobastion-session "$@"
}

assert_shared_sudo_policy() {
  test "$sudo_policy" = "$(sha256sum /etc/sudoers.d/gobastion-session)"
  test ! -e /etc/sudoers.d/admin
  test ! -e /etc/sudoers.d/target
}

assert_retired_identity() {
  test "$(id -u target)" = "$target_uid"
  test "$(getent passwd target | cut -d: -f6)" = "$target_home"
  grep -qx 'preserve retirement identity' "$target_home/retirement-marker"
  test ! -s "$target_home/.ssh/authorized_keys"
  test -d /app/ttyrec/target
  test ! -L /app/ttyrec/target
  test "$(stat -c '%u:%g:%a' /app/ttyrec/target)" = "0:$(getent group gobastion-auditors | cut -d: -f3):2750"
}

step=account-creation
printf '%s\n' "$public_key" | as_admin '-osh accountCreate --user target' > "$test_dir/create.out" 2>&1
grep -q 'created successfully' "$test_dir/create.out"
as_admin '-osh accountModify --user target --sysrole admin' > "$test_dir/modify.out" 2>&1
grep -q 'system role: admin' "$test_dir/modify.out"
assert_shared_sudo_policy
test -s /home/target/.ssh/authorized_keys
target_uid=$(id -u target)
target_home=$(getent passwd target | cut -d: -f6)
su-exec target env HOME="$target_home" \
  sh -c 'printf "preserve retirement identity\n" > "$HOME/retirement-marker"'

# The command must reach the root collector with kernel-supplied identity;
# ordinary account processes cannot read or append to the audit file directly.
step=audit-boundary
kill -0 "$audit_pid"
test "$(stat -c '%u:%g:%a' /goBastion.log)" = '0:0:600'
if su-exec admin sh -c 'cat /goBastion.log > /dev/null' > "$test_dir/audit-read.out" 2>&1; then
  echo 'ordinary account read the root audit file directly' >&2
  exit 1
fi
if su-exec admin sh -c ': >> /goBastion.log' > "$test_dir/audit-write.out" 2>&1; then
  echo 'ordinary account opened the root audit file for writing' >&2
  exit 1
fi
jq -se --argjson uid "$(id -u admin)" '
  any(.[]; .event_type == "command" and ._collector_uid == $uid
    and (._collector_pid | type == "number" and . > 0)
    and (._collector_event_id | type == "string" and length > 0))
' /goBastion.log > /dev/null
echo 'PASS: root audit permissions and collector command identity enforced'

# Refuse self-deletion even when another administrator exists.
step=self-deletion
if as_admin '-osh accountDelete --user admin' > "$test_dir/delete-self.out" 2>&1; then
  echo 'self-deletion unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'cannot delete your own account' "$test_dir/delete-self.out"
getent passwd admin > /dev/null

# Revoke an established target process and ingress keys without releasing UID.
step=session-revocation
su-exec target sleep 600 &
target_pid=$!
as_admin '-osh accountExpire --user target' > "$test_dir/expire.out" 2>&1
grep -q 'locked immediately' "$test_dir/expire.out"
timeout 30 /app/goBastion --sync > "$test_dir/sync.out" 2>&1
attempt=0
while kill -0 "$target_pid" 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 50 ] || { echo 'disabled account process survived sync' >&2; exit 1; }
  sleep 0.1
done
wait "$target_pid" 2>/dev/null || true
target_pid=
assert_shared_sudo_policy
test ! -s "$target_home/.ssh/authorized_keys"
echo 'PASS: disabled account processes and ingress keys revoked'

step=account-retirement
as_admin '-osh accountDelete --user target' > "$test_dir/retire.out" 2>&1
grep -q 'retired' "$test_dir/retire.out"
assert_retired_identity
if printf '%s\n' "$public_key" | as_admin '-osh accountCreate --user target' > "$test_dir/reuse.out" 2>&1; then
  echo 'retired account name unexpectedly reused' >&2
  exit 1
fi
grep -q 'retired login name cannot be reused' "$test_dir/reuse.out"
assert_retired_identity

# Legacy helpers delegate to DB-backed reconciliation. Neither their names nor
# their old action arguments authorize native account creation/deletion.
step=legacy-helpers
/usr/local/sbin/gobastion-deluser target > "$test_dir/legacy-delete.out" 2>&1
assert_retired_identity
if /usr/local/sbin/gobastion-adduser untracked > "$test_dir/legacy-create.out" 2>&1; then
  echo 'legacy helper accepted an account absent from DB' >&2
  exit 1
fi
if getent passwd untracked > /dev/null; then
  echo 'legacy helper created an account absent from DB' >&2
  exit 1
fi
test ! -e /home/untracked
assert_shared_sudo_policy
echo 'PASS: retired UID/home retained, name reuse refused and legacy helpers constrained'

# Account-only mode must reject every interactive entry point without a PTY.
step=interactive-restrictions
as_admin '-osh accountModify --user admin --oshOnly true' > "$test_dir/osh.out" 2>&1
if as_admin '--' > "$test_dir/interactive.out" 2>&1; then
  echo 'restricted interactive entry point unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'Interactive mode is disabled' "$test_dir/interactive.out"
if as_admin '-osh' > "$test_dir/empty-osh.out" 2>&1; then
  echo 'empty -osh command unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'Usage:' "$test_dir/empty-osh.out"
echo 'PASS: restricted interactive entry points denied'
