#!/bin/sh
# Called by test-db-isolation.sh inside its disposable container/DB fixtures.
set -eu
trap 'status=$?; if [ "$status" != 0 ]; then cat /tmp/db-supervisor-*.out 2>/dev/null || true; fi' EXIT
mkdir -p /run/gobastion
chmod 0700 /run/gobastion
export EGRESS_ENC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
printf 'EGRESS_ENC_KEY=%s\n' "$EGRESS_ENC_KEY" > /run/gobastion/db.conf
chmod 0600 /run/gobastion/db.conf
ssh-keygen -q -t ed25519 -N '' -f /tmp/db-supervisor-ingress
public_key=$(cat /tmp/db-supervisor-ingress.pub)
printf 'admin\n%s\n' "$public_key" | /app/goBastion --firstInstall > /tmp/db-supervisor-bootstrap.out
as_admin() { su-exec admin env HOME=/home/admin /app/goBastion "$@"; }
as_admin '-osh selfAddDBAccess --host db.fixture --port 55432 --protocol postgres --user credentialuser --password sandbox-secret --database postgres' > /tmp/db-supervisor-access.out
grep -q 'Personal DB access added successfully' /tmp/db-supervisor-access.out
# Split the SQL literal so terminal input echo cannot satisfy the assertion.
printf "SELECT 'SUPERVISOR_' || 'OK';\n\\\\q\n" | as_admin --db credentialuser@db.fixture:55432:postgres > /tmp/db-supervisor-session.out 2>&1
grep -q 'SUPERVISOR_OK' /tmp/db-supervisor-session.out
grep -Fq -- '- account-admin' /tmp/db-supervisor-session.out
[ "$(grep -Fc '.,,.      .,,.' /tmp/db-supervisor-session.out)" = 1 ]
[ "$(grep -Fc 'Welcome to goBastion, admin!' /tmp/db-supervisor-session.out)" = 1 ]
grep -Fq 'Last login:' /tmp/db-supervisor-session.out
recording=$(find /app/ttyrec/admin -type f -name '*.ttyrec.gz' | head -1)
test -n "$recording"
gzip -dc "$recording" | grep -q 'SUPERVISOR_OK'
echo 'PASS: --db supervisor, encrypted credentials and compressed recording'

# Exercise hostname lookup and nonempty MySQL credentials through the same
# sudo supervisor path, rather than only launching a native client by IP.
as_admin '-osh selfAddDBAccess --host db.fixture --port 53306 --protocol mysql --user credentialuser --password sandbox-secret' > /tmp/db-supervisor-mysql-access.out
grep -q 'Personal DB access added successfully' /tmp/db-supervisor-mysql-access.out
printf "system env\nSELECT CONCAT('MYSQL_SUPERVISOR_', 'OK');\n\\\\q\n" | as_admin --db credentialuser@db.fixture:53306:mysql > /tmp/db-supervisor-mysql-session.out 2>&1
grep -q 'MYSQL_SUPERVISOR_OK' /tmp/db-supervisor-mysql-session.out
if grep -Eq 'MYSQL_PWD=|PGPASSWORD=|REDISCLI_AUTH=|sandbox-secret|insecure passwordless login' /tmp/db-supervisor-mysql-session.out; then
 echo 'FAIL: native MySQL client received credentials or disabled upstream verification' >&2; exit 1
fi
mysql_recording=$(find /app/ttyrec/admin/db.fixture -type f -name '*:53306_*.ttyrec.gz' | head -1)
test -n "$mysql_recording"
gzip -dc "$mysql_recording" | grep -q 'MYSQL_SUPERVISOR_OK'
echo 'PASS: MySQL hostname, encrypted password and compressed recording'

# The source must describe the selected grant, including a group inherited by
# a non-administrator, rather than the alias owner or an administrative override.
printf '%s\n' "$public_key" | as_admin '-osh accountCreate --user dbclient' > /tmp/db-supervisor-create.out
as_dbclient() { su-exec dbclient env HOME=/home/dbclient /app/goBastion "$@"; }
as_admin '-osh groupCreate --group PLEX' > /tmp/db-supervisor-group.out
as_admin '-osh groupAddMember --group PLEX --user dbclient --role member' > /tmp/db-supervisor-member.out
as_admin '-osh groupAddDBAccess --group PLEX --host db.fixture --port 53306 --protocol mysql --user credentialuser --password sandbox-secret' > /tmp/db-supervisor-group-access.out
printf "SELECT CONCAT('GROUP_SUPERVISOR_', 'OK');\n\\\\q\n" | as_dbclient --db credentialuser@db.fixture:53306:mysql > /tmp/db-supervisor-group-session.out 2>&1
grep -q 'GROUP_SUPERVISOR_OK' /tmp/db-supervisor-group-session.out
grep -Fq -- '- group-PLEX' /tmp/db-supervisor-group-session.out
[ "$(grep -Fc '.,,.      .,,.' /tmp/db-supervisor-group-session.out)" = 1 ]
[ "$(grep -Fc 'Welcome to goBastion, dbclient!' /tmp/db-supervisor-group-session.out)" = 1 ]
echo 'PASS: DB welcome shown once and selected group access displayed'

as_admin '-osh groupDelete --group PLEX' > /tmp/db-supervisor-delete-group.out
grep -q "Group 'PLEX' deleted successfully" /tmp/db-supervisor-delete-group.out
printf "SELECT CONCAT('DELETED_GROUP_', 'BYPASS');\n" | as_dbclient --db credentialuser@db.fixture:53306:mysql > /tmp/db-supervisor-deleted-group.out 2>&1
if grep -q DELETED_GROUP_BYPASS /tmp/db-supervisor-deleted-group.out; then
 echo 'FAIL: deleted group still grants a supervised DB session' >&2; exit 1
fi
grep -q 'no database access found' /tmp/db-supervisor-deleted-group.out
echo 'PASS: group deletion revokes the supervised DB access'

# Revoking the frontend UID must also stop its root supervisor and DB client.
as_dbclient '-osh selfAddDBAccess --host 127.0.0.1 --port 55432 --protocol postgres --user credentialuser --password sandbox-secret --database postgres' > /tmp/db-supervisor-client-access.out
printf 'SELECT pg_sleep(60);\n' | as_dbclient --db credentialuser@127.0.0.1:55432:postgres > /tmp/db-supervisor-revoked.out 2>&1 &
live_frontend=$!
active_queries() {
 psql -Atq -h127.0.0.1 -p55432 -Upostgres -dpostgres -c "SELECT count(*) FROM pg_stat_activity WHERE usename='credentialuser' AND state='active' AND query LIKE 'SELECT pg_sleep%'"
}
ready=no
for attempt in $(seq 1 50); do
 if [ "$(active_queries)" = 1 ]; then ready=yes; break; fi
 sleep 0.1
done
[ "$ready" = yes ] || { echo 'FAIL: supervised DB query never started' >&2; exit 1; }
# Recovery must leave the live recorder untouched, including its inherited lock.
lock_seen=no
for recorder_pid in $(pgrep -x ttyrec); do
 for descriptor in /proc/$recorder_pid/fd/*; do
  target=$(readlink "$descriptor" 2>/dev/null || true)
  case "$target" in */.db-pending/*/.lock) lock_seen=yes ;; esac
 done
done
[ "$lock_seen" = yes ] || { echo 'FAIL: ttyrec did not inherit its recording lock' >&2; exit 1; }
/app/goBastion --sync >/tmp/db-supervisor-active-sync.out 2>&1
[ "$(active_queries)" -ge 1 ] || { echo 'FAIL: sync interrupted an active DB recording' >&2; exit 1; }
echo 'PASS: sync skips active DB recording and ttyrec retains its lock'
as_admin '-osh accountExpire --user dbclient' > /tmp/db-supervisor-expire.out
stopped=no
for attempt in $(seq 1 50); do
 if [ "$(active_queries)" = 0 ]; then stopped=yes; break; fi
 sleep 0.1
done
[ "$stopped" = yes ] || { echo 'FAIL: DB query survived account revocation' >&2; exit 1; }
wait "$live_frontend" 2>/dev/null || true
echo 'PASS: account revocation closes the supervised DB connection'

if env SUDO_USER=admin SUDO_UID=999 /app/goBastion --dbSession credentialuser@127.0.0.1:55432:postgres > /tmp/db-supervisor-spoof.out 2>&1; then
 echo 'FAIL: mismatched sudo actor accepted' >&2; exit 1
fi
as_admin '-osh accountModify --user admin --oshOnly true' > /tmp/db-supervisor-policy.out
printf "SELECT 'POLICY_' || 'BYPASS';\n" | as_admin --db credentialuser@127.0.0.1:55432:postgres > /tmp/db-supervisor-denied.out 2>&1
if grep -q POLICY_BYPASS /tmp/db-supervisor-denied.out; then
 echo 'FAIL: account-only restriction bypassed' >&2; exit 1
fi
echo 'PASS: DB supervisor rejects spoofed actor and account-only access'
