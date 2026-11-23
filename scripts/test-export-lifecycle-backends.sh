#!/usr/bin/env bash
# Verify export snapshot lifetime and pre-migration backups on disposable backends.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
go_bin=${GO_BIN:-go}
postgres_image=${GOB_EXPORT_POSTGRES_IMAGE:-postgres:17-alpine}
mysql_image=${GOB_EXPORT_MYSQL_IMAGE:-mariadb:11.4}
postgres_port=${GOB_EXPORT_POSTGRES_PORT:-55441}
mysql_port=${GOB_EXPORT_MYSQL_PORT:-55442}
backend_choice=${GOB_EXPORT_BACKENDS:-all}
fixture_password=gobastion-export-test-only
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/gobastion-export-lifecycle.XXXXXX")
container_name=
fixture_image=
image_preexisting=yes

cleanup_fixture() {
  if [[ -n "$container_name" ]] && docker container inspect "$container_name" >/dev/null 2>&1; then
    docker rm -fv "$container_name" >/dev/null
  fi
  container_name=
  if [[ -n "$fixture_image" && "$image_preexisting" == no ]]; then
    docker image rm "$fixture_image" >/dev/null || echo 'New test image retained because Docker refused safe removal.' >&2
  fi
  fixture_image=
}
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  cleanup_fixture || status=1
  rm -rf -- "$test_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

command -v docker >/dev/null 2>&1 || { echo 'Docker is required.' >&2; exit 1; }
command -v "$go_bin" >/dev/null 2>&1 || { echo 'Set GO_BIN to the installed Go executable.' >&2; exit 1; }
case "$backend_choice" in all|postgres|mysql) ;; *) echo 'GOB_EXPORT_BACKENDS must be all, postgres or mysql.' >&2; exit 2 ;; esac
for port in "$postgres_port" "$mysql_port"; do
  [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1024 && port <= 65535)) || { echo 'Fixture ports must be unprivileged TCP ports.' >&2; exit 2; }
  if command -v ss >/dev/null 2>&1 && [[ -n "$(ss -H -ltn "sport = :$port")" ]]; then
    echo "Fixture port $port is in use." >&2
    exit 1
  fi
done
[[ "$postgres_port" != "$mysql_port" ]] || { echo 'Fixture ports must differ.' >&2; exit 2; }
docker version --format '{{.Server.Version}}' >/dev/null
"$go_bin" test -c -o "$test_dir/export.test" "$repo_root/internal/db"

if [[ "$backend_choice" == all || "$backend_choice" == postgres ]]; then
fixture_image=$postgres_image
image_preexisting=no
docker image inspect "$fixture_image" >/dev/null 2>&1 && image_preexisting=yes
container_name="gobastion-export-pg-$$-${RANDOM}"
docker run --detach --name "$container_name" --label gobastion.test=export-lifecycle \
  --publish "127.0.0.1:$postgres_port:5432" \
  --env "POSTGRES_PASSWORD=$fixture_password" --env POSTGRES_DB=gobastion_export \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=256m \
  "$fixture_image" >/dev/null
ready=no
for ((attempt = 0; attempt < 90; attempt++)); do
  if docker exec "$container_name" pg_isready --host 127.0.0.1 --username postgres >/dev/null 2>&1; then ready=yes; break; fi
  sleep 1
done
[[ "$ready" == yes ]] || { docker logs --tail 30 "$container_name" >&2; exit 1; }
GOB_EXPORT_LIFECYCLE_DRIVER=postgres \
  GOB_EXPORT_LIFECYCLE_DSN="host=127.0.0.1 port=$postgres_port user=postgres password=$fixture_password dbname=gobastion_export sslmode=disable connect_timeout=5" \
  "$test_dir/export.test" -test.run '^TestBackendExport(SnapshotLifecycle|UpgradeRevocationEpoch)$' -test.count=1 -test.timeout=180s -test.v
cleanup_fixture
fi

if [[ "$backend_choice" == all || "$backend_choice" == mysql ]]; then
fixture_image=$mysql_image
image_preexisting=no
docker image inspect "$fixture_image" >/dev/null 2>&1 && image_preexisting=yes
container_name="gobastion-export-mysql-$$-${RANDOM}"
docker run --detach --name "$container_name" --label gobastion.test=export-lifecycle \
  --publish "127.0.0.1:$mysql_port:3306" \
  --env "MYSQL_ROOT_PASSWORD=$fixture_password" --env MYSQL_ROOT_HOST=% --env MYSQL_DATABASE=gobastion_export \
  --tmpfs /var/lib/mysql:rw,nosuid,nodev,noexec,size=384m \
  "$fixture_image" >/dev/null
ready=no
for ((attempt = 0; attempt < 90; attempt++)); do
  if docker exec --env "MYSQL_PWD=$fixture_password" "$container_name" sh -c \
    'if command -v mariadb-admin >/dev/null 2>&1; then exec mariadb-admin --protocol=tcp --host=127.0.0.1 --user=root ping --silent; else exec mysqladmin --protocol=tcp --host=127.0.0.1 --user=root ping --silent; fi' >/dev/null 2>&1; then ready=yes; break; fi
  sleep 1
done
[[ "$ready" == yes ]] || { docker logs --tail 30 "$container_name" >&2; exit 1; }
GOB_EXPORT_LIFECYCLE_DRIVER=mysql \
  GOB_EXPORT_LIFECYCLE_DSN="root:$fixture_password@tcp(127.0.0.1:$mysql_port)/gobastion_export?charset=utf8mb4&parseTime=True&timeout=5s&readTimeout=10s&writeTimeout=10s" \
  "$test_dir/export.test" -test.run '^TestBackendExport(SnapshotLifecycle|UpgradeRevocationEpoch)$' -test.count=1 -test.timeout=180s -test.v
cleanup_fixture
fi
echo "PASS: $backend_choice export snapshot lifecycle and upgrade checks"
