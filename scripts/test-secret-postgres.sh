#!/usr/bin/env bash
# Run PostgreSQL secret migration and encrypted logical export/import checks in
# one invocation. Only this script's container and newly pulled image are removed.
# Example:
# GO_BIN=/home/phd/go/go1.27.3/bin/go \
# GOCACHE=/tmp/gobastion-mission-cache GOPATH=/tmp/gobastion-mission-go \
#   scripts/test-secret-postgres.sh
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
go_bin=${GO_BIN:-go}
postgres_image=${GOB_SECRET_POSTGRES_IMAGE:-postgres:17-alpine}
postgres_port=${GOB_SECRET_POSTGRES_PORT:-55439}
container_name="gobastion-secret-postgres-$$-${RANDOM}"
# Disposable fixture credential, never used for a deployment or external server.
postgres_password=gobastion-secret-postgres-test-only

if ! command -v docker >/dev/null 2>&1; then
  echo 'Docker is required for PostgreSQL integration checks.' >&2
  exit 1
fi
if ! command -v "$go_bin" >/dev/null 2>&1; then
  echo 'Set GO_BIN to the installed Go executable.' >&2
  exit 1
fi
if [[ ! "$postgres_port" =~ ^[0-9]+$ ]] || ((postgres_port < 1024 || postgres_port > 65535)); then
  echo 'GOB_SECRET_POSTGRES_PORT must be an unprivileged TCP port.' >&2
  exit 1
fi
# Refuse an occupied host port; never stop or replace an existing listener.
# Docker's bind check remains authoritative if ss is unavailable or another
# process binds between this check and docker run.
if command -v ss >/dev/null 2>&1 && [[ -n "$(ss -H -ltn "sport = :$postgres_port")" ]]; then
  echo "PostgreSQL test port $postgres_port is already in use." >&2
  exit 1
fi

docker version --format '{{.Server.Version}}' >/dev/null
postgres_image_preexisting=no
if docker image inspect "$postgres_image" >/dev/null 2>&1; then
  postgres_image_preexisting=yes
fi
printf 'postgres_image_preexisting=%s image=%s\n' "$postgres_image_preexisting" "$postgres_image"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if docker container inspect "$container_name" >/dev/null 2>&1; then
    if ! docker rm -fv "$container_name" >/dev/null; then
      echo "Could not remove test container $container_name." >&2
      status=1
    fi
  fi
  if [[ "$postgres_image_preexisting" == no ]]; then
    # Do not force image deletion: another container may have begun using it.
    # Existing images and all unrelated Docker resources are always retained.
    image_id=$(docker image inspect "$postgres_image" --format '{{.Id}}' 2>/dev/null || true)
    if [[ -n "$image_id" ]] && ! docker image rm "$image_id" >/dev/null; then
      echo 'New PostgreSQL image retained because Docker refused safe removal.' >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

# A tmpfs data directory keeps this disposable fixture off the host disk and
# avoids allocating a persistent Docker volume. It is removed with the container.
docker run --detach --name "$container_name" \
  --label gobastion.mission=production-hardening \
  --publish "127.0.0.1:$postgres_port:5432" \
  --env "POSTGRES_PASSWORD=$postgres_password" \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=256m \
  "$postgres_image" >/dev/null

ready=no
for ((attempt = 0; attempt < 60; attempt++)); do
  # TCP avoids accepting the temporary Unix-socket-only initialization server.
  if docker exec "$container_name" pg_isready --host 127.0.0.1 --username postgres >/dev/null 2>&1; then
    ready=yes
    break
  fi
  sleep 1
done
if [[ "$ready" != yes ]]; then
  echo 'Disposable PostgreSQL did not become ready.' >&2
  docker logs --tail 50 "$container_name" >&2 || true
  exit 1
fi

docker exec "$container_name" psql --username postgres --dbname postgres \
  --set ON_ERROR_STOP=1 \
  --command 'CREATE DATABASE mission_secrets;' \
  --command 'CREATE DATABASE mission_source;' \
  --command 'CREATE DATABASE mission_target;' \
  --command 'CREATE DATABASE mission_observability;' >/dev/null

base_dsn="host=127.0.0.1 port=$postgres_port user=postgres password=$postgres_password sslmode=disable connect_timeout=5"
export GOB_SECRET_POSTGRES_DSN="$base_dsn dbname=mission_secrets"
export GOB_OBSERVABILITY_POSTGRES_DSN="$base_dsn dbname=mission_observability"
export GOB_INTEGRATION_DB_DRIVER=postgres
export GOB_INTEGRATION_TARGET_DB_DRIVER=postgres
export GOB_INTEGRATION_SOURCE_DSN="$base_dsn dbname=mission_source"
export GOB_INTEGRATION_TARGET_DSN="$base_dsn dbname=mission_target"
# Test-only encryption configuration; never fall back to deployment key files.
export EGRESS_ENC_KEY=PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo=
unset EGRESS_ENC_KEY_FILE EGRESS_ENC_KEY_ID EGRESS_ENC_KEYS EGRESS_ENC_KEYS_FILE
unset GOB_SECRETSTORE_HELPER_MODE GOB_SECRETSTORE_HELPER_PATH

cd -- "$repo_root"
"$go_bin" test -count=1 -timeout=120s -v \
  ./internal/secretstore ./internal/db ./internal/observability \
  -run '^(TestPostgres.*|TestBackendIntegration)$'
