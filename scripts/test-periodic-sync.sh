#!/bin/sh
# Exercise the entrypoint's actual periodic-sync function without root or Docker.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/gobastion-periodic-sync.XXXXXX")
sync_pid=
cleanup() {
  [ -z "$sync_pid" ] || kill "$sync_pid" 2>/dev/null || true
  [ -z "$sync_pid" ] || wait "$sync_pid" 2>/dev/null || true
  rm -rf "$test_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

sed -n '/^periodic_sync() {/,/^}/p' "$repo_dir/entrypoint.sh" > "$test_dir/function.sh"
grep -q '^periodic_sync() {' "$test_dir/function.sh"
# shellcheck source=/dev/null
. "$test_dir/function.sh"

export TEST_SYNC_COUNT="$test_dir/count" TEST_SYNC_GATE="$test_dir/recover"
cat > "$test_dir/mock-sync" <<'MOCK'
#!/bin/sh
set -eu
[ "$#" -eq 1 ] && [ "$1" = --sync ]
count=0
[ ! -f "$TEST_SYNC_COUNT" ] || count=$(cat "$TEST_SYNC_COUNT")
count=$((count + 1))
printf '%s\n' "$count" > "$TEST_SYNC_COUNT"
if [ "$count" -eq 1 ]; then
  exit 23
fi
while [ ! -e "$TEST_SYNC_GATE" ]; do sleep 0.1; done
MOCK
chmod 0700 "$test_dir/mock-sync"

SYNC_INTERVAL=1
SYNC_RETRY=1
SYNC_HEALTH_FILE="$test_dir/sync.healthy"
SYNC_LAST_SUCCESS_FILE="$test_dir/sync.last_success"
HOSTNAME=test
: > "$SYNC_HEALTH_FILE"
printf '0\n' > "$SYNC_LAST_SUCCESS_FILE"
periodic_sync "$test_dir/mock-sync" > "$test_dir/log" 2>&1 &
sync_pid=$!

attempt=0
while ! grep -q '"_event":"sync_failed"' "$test_dir/log"; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 50 ] || { echo 'periodic sync did not report failure' >&2; exit 1; }
  sleep 0.1
done
test ! -e "$SYNC_HEALTH_FILE"
test "$(cat "$SYNC_LAST_SUCCESS_FILE")" -eq 0
grep -q '"_exit_code":23' "$test_dir/log"

attempt=0
while [ ! -e "$TEST_SYNC_COUNT" ] || [ "$(cat "$TEST_SYNC_COUNT")" -lt 2 ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 50 ] || { echo 'periodic sync did not retry' >&2; exit 1; }
  sleep 0.1
done
test ! -e "$SYNC_HEALTH_FILE"
: > "$TEST_SYNC_GATE"
attempt=0
while [ ! -e "$SYNC_HEALTH_FILE" ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 50 ] || { echo 'periodic sync did not recover health' >&2; exit 1; }
  sleep 0.1
done
test "$(cat "$SYNC_LAST_SUCCESS_FILE")" -gt 0
kill -0 "$sync_pid"
echo 'PASS: periodic sync retries after failure and restores health after recovery'
