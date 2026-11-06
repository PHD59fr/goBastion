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
as_admin '-osh selfAddDBAccess --host 127.0.0.1 --port 55432 --protocol postgres --user credentialuser --password sandbox-secret --database postgres' > /tmp/db-supervisor-access.out
grep -q 'Personal DB access added successfully' /tmp/db-supervisor-access.out
# Split the SQL literal so terminal input echo cannot satisfy the assertion.
printf "SELECT 'SUPERVISOR_' || 'OK';\n\\\\q\n" | as_admin --db credentialuser@127.0.0.1:55432:postgres > /tmp/db-supervisor-session.out 2>&1
grep -q 'SUPERVISOR_OK' /tmp/db-supervisor-session.out
recording=$(find /app/ttyrec/admin -type f -name '*.ttyrec.gz' | head -1)
test -n "$recording"
gzip -dc "$recording" | grep -q 'SUPERVISOR_OK'
echo 'PASS: --db supervisor, encrypted credentials and compressed recording'

# Revoking the frontend UID must also stop its root supervisor and DB client.
printf '%s\n' "$public_key" | as_admin '-osh accountCreate --user dbclient' > /tmp/db-supervisor-create.out
as_dbclient() { su-exec dbclient env HOME=/home/dbclient /app/goBastion "$@"; }
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
