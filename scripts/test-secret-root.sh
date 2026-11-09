#!/bin/sh
# Root-only CLI tests in a small disposable container. No host root execution.
set -eu
GO_BIN=${GO_BIN:-go}
# Optional acceptance audit exercises account confidentiality and namespace
# isolation with distinct ordinary-user and administrator credentials.
recording_exposure_audit=${GOB_TEST_RECORDING_EXPOSURE_AUDIT:-0}
case "$recording_exposure_audit" in 0|1) ;; *) echo "GOB_TEST_RECORDING_EXPOSURE_AUDIT must be 0 or 1" >&2; exit 2 ;; esac
image=alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
had_image=false
docker image inspect "$image" >/dev/null 2>&1 && had_image=true
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/gobastion-root-test.XXXXXX")
container_id=
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$container_id" ] && docker container inspect "$container_id" >/dev/null 2>&1; then
    if ! docker rm -fv "$container_id" >/dev/null; then
      echo "Could not remove mission test container $container_id" >&2
      status=1
    fi
  fi
  if [ "$had_image" = false ] && docker image inspect "$image" >/dev/null 2>&1; then
    if ! docker image rm "$image" >/dev/null; then
      echo "New Alpine image retained because Docker refused safe removal" >&2
    fi
  fi
  rm -rf "$test_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
CGO_ENABLED=0 "$GO_BIN" test -c -o "$test_dir/secret-migrate.test" ./cmd/secret-migrate
CGO_ENABLED=0 "$GO_BIN" test -c -o "$test_dir/recording-admin.test" ./cmd/recording-admin
CGO_ENABLED=0 "$GO_BIN" test -c -o "$test_dir/observability.test" ./cmd/observability
CGO_ENABLED=0 "$GO_BIN" test -c -o "$test_dir/reconcilelock.test" ./internal/reconcilelock
CGO_ENABLED=0 "$GO_BIN" test -c -o "$test_dir/sync.test" ./internal/utils/sync
CGO_ENABLED=0 "$GO_BIN" test -c -o "$test_dir/recording.test" ./internal/recording
CGO_ENABLED=0 "$GO_BIN" test -c -o "$test_dir/osadapter.test" ./internal/osadapter
container_id=$(docker create --network none --label gobastion.mission=production-hardening \
  --env GOB_TEST_ROOT_RECONCILE_LOCK=1 \
  --env GOB_TEST_ROOT_SSH_PUBLISH=1 \
  --env GOB_TEST_ROOT_SSH_SPOOL=1 \
  --env "GOB_TEST_RECORDING_EXPOSURE_AUDIT=$recording_exposure_audit" \
  --mount "type=bind,source=$test_dir/secret-migrate.test,target=/secret-migrate.test,readonly" \
  --mount "type=bind,source=$test_dir/recording-admin.test,target=/recording-admin.test,readonly" \
  --mount "type=bind,source=$test_dir/observability.test,target=/observability.test,readonly" \
  --mount "type=bind,source=$test_dir/reconcilelock.test,target=/reconcilelock.test,readonly" \
  --mount "type=bind,source=$test_dir/sync.test,target=/sync.test,readonly" \
  --mount "type=bind,source=$test_dir/recording.test,target=/recording.test,readonly" \
  --mount "type=bind,source=$test_dir/osadapter.test,target=/osadapter.test,readonly" \
  --entrypoint /bin/sh "$image" -c 'addgroup -g 1001 gobastion && addgroup -g 1005 gobastion-auditors && adduser -D -u 1001 -G gobastion recording-test && adduser -D -u 1000 -G gobastion victim && adduser -D -u 1002 -G gobastion attacker && adduser -D -u 1003 -G gobastion future && adduser -D -u 1004 -G gobastion administrator && addgroup administrator gobastion-auditors && mkdir -p /app/ttyrec && chown root:gobastion /app/ttyrec && chmod 0751 /app/ttyrec && /secret-migrate.test -test.v && /recording-admin.test -test.v && /observability.test -test.v && /reconcilelock.test -test.v && /osadapter.test -test.run="^(TestRootLegacySudoersRemoval|TestRootLegacySudoersRejectsSymlink|TestRootLegacySudoersRejectsUnrelatedPolicy)$" -test.v && /sync.test -test.run="^(TestRootLinuxSSHPublication|TestRootRecordingAuditorRevocation|TestRootRecordingAccountRetirementWorkflow)$" -test.v && /recording.test -test.run="^(TestArchiveRejectsExtendedACL|TestRootSSHSpool|TestRootRecordingStickyDirectories|TestRootRecordingAccount.*|TestRootRecordingProvision.*|TestRootRecordingExposureAudit)$" -test.v')
docker start -a "$container_id"
status=$(docker inspect --format '{{.State.ExitCode}}' "$container_id")
test "$status" -eq 0
