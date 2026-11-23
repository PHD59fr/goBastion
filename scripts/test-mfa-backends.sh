#!/usr/bin/env bash
# Verify TOTP consumption against SQLite, PostgreSQL and the MySQL dialect.
# The default MySQL service is MariaDB; set GOB_MFA_MYSQL_IMAGE=mysql:8.4 to
# exercise Oracle MySQL instead. Services run sequentially and use only tmpfs
# data directories. This script removes only its containers and newly pulled
# images, and never prunes Docker resources.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
go_bin=${GO_BIN:-go}
postgres_image=${GOB_MFA_POSTGRES_IMAGE:-postgres:17-alpine}
mysql_image=${GOB_MFA_MYSQL_IMAGE:-mariadb:11.4}
postgres_port=${GOB_MFA_POSTGRES_PORT:-55439}
mysql_port=${GOB_MFA_MYSQL_PORT:-55438}
race=${GOB_MFA_TEST_RACE:-0}
# Disposable fixture credential; no deployment credentials are loaded.
fixture_password=gobastion-mfa-test-only
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/gobastion-mfa-backends.XXXXXX")
container_name=
fixture_image=
image_preexisting=yes

cleanup_fixture() {
  if [[ -n "$container_name" ]] && docker container inspect "$container_name" >/dev/null 2>&1; then
    docker rm -fv "$container_name" >/dev/null
  fi
  container_name=
  if [[ -n "$fixture_image" && "$image_preexisting" == no ]]; then
    # Do not force deletion if another container started using the image.
    if ! docker image rm "$fixture_image" >/dev/null; then
      echo 'New test image retained because Docker refused safe removal.' >&2
    fi
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

command -v docker >/dev/null 2>&1 || { echo 'Docker is required for MFA backend checks.' >&2; exit 1; }
command -v "$go_bin" >/dev/null 2>&1 || { echo 'Set GO_BIN to the installed Go executable.' >&2; exit 1; }
case "$race" in 0|1) ;; *) echo 'GOB_MFA_TEST_RACE must be 0 or 1.' >&2; exit 2 ;; esac
for port in "$postgres_port" "$mysql_port"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1024 || port > 65535)); then
    echo 'MFA fixture ports must be unprivileged TCP ports.' >&2
    exit 2
  fi
  if command -v ss >/dev/null 2>&1 && [[ -n "$(ss -H -ltn "sport = :$port")" ]]; then
    echo "MFA fixture port $port is already in use." >&2
    exit 1
  fi
done
[[ "$postgres_port" != "$mysql_port" ]] || { echo 'MFA fixture ports must be distinct.' >&2; exit 2; }
docker version --format '{{.Server.Version}}' >/dev/null

build_flags=()
if [[ "$race" == 1 ]]; then build_flags+=(-race); fi
"$go_bin" test "${build_flags[@]}" -c -o "$test_dir/mfa.test" "$repo_root/internal/mfa"
unset GOB_MFA_INTEGRATION_DRIVER GOB_MFA_INTEGRATION_DSN GOB_MFA_INTEGRATION_DISPOSABLE
"$test_dir/mfa.test" -test.run '^TestTOTPBackendIntegration$' -test.count=1 -test.timeout=180s -test.v

fixture_image=$postgres_image
image_preexisting=no
docker image inspect "$fixture_image" >/dev/null 2>&1 && image_preexisting=yes
container_name="gobastion-mfa-postgres-$$-${RANDOM}"
docker run --detach --name "$container_name" --label gobastion.test=mfa-backends \
  --publish "127.0.0.1:$postgres_port:5432" \
  --env "POSTGRES_PASSWORD=$fixture_password" --env POSTGRES_DB=gobastion_mfa \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=256m \
  "$fixture_image" >/dev/null
ready=no
for ((attempt = 0; attempt < 90; attempt++)); do
  if docker exec "$container_name" pg_isready --host 127.0.0.1 --username postgres >/dev/null 2>&1; then
    ready=yes
    break
  fi
  sleep 1
done
if [[ "$ready" != yes ]]; then
  echo 'Disposable PostgreSQL did not become ready.' >&2
  docker logs --tail 30 "$container_name" >&2 || true
  exit 1
fi
GOB_MFA_INTEGRATION_DRIVER=postgres GOB_MFA_INTEGRATION_DISPOSABLE=1 \
  GOB_MFA_INTEGRATION_DSN="host=127.0.0.1 port=$postgres_port user=postgres password=$fixture_password dbname=gobastion_mfa sslmode=disable connect_timeout=5" \
  "$test_dir/mfa.test" -test.run '^TestTOTPBackendIntegration$' -test.count=1 -test.timeout=180s -test.v
cleanup_fixture

fixture_image=$mysql_image
image_preexisting=no
docker image inspect "$fixture_image" >/dev/null 2>&1 && image_preexisting=yes
container_name="gobastion-mfa-mysql-$$-${RANDOM}"
docker run --detach --name "$container_name" --label gobastion.test=mfa-backends \
  --publish "127.0.0.1:$mysql_port:3306" \
  --env "MYSQL_ROOT_PASSWORD=$fixture_password" --env MYSQL_ROOT_HOST=% --env MYSQL_DATABASE=gobastion_mfa \
  --tmpfs /var/lib/mysql:rw,nosuid,nodev,noexec,size=384m \
  "$fixture_image" >/dev/null
ready=no
for ((attempt = 0; attempt < 90; attempt++)); do
  if docker exec --env "MYSQL_PWD=$fixture_password" "$container_name" sh -c \
    'if command -v mariadb-admin >/dev/null 2>&1; then exec mariadb-admin --protocol=tcp --host=127.0.0.1 --user=root ping --silent; else exec mysqladmin --protocol=tcp --host=127.0.0.1 --user=root ping --silent; fi' >/dev/null 2>&1; then
    ready=yes
    break
  fi
  sleep 1
done
if [[ "$ready" != yes ]]; then
  echo 'Disposable MySQL-compatible service did not become ready.' >&2
  docker logs --tail 30 "$container_name" >&2 || true
  exit 1
fi
GOB_MFA_INTEGRATION_DRIVER=mysql GOB_MFA_INTEGRATION_DISPOSABLE=1 \
  GOB_MFA_INTEGRATION_DSN="root:$fixture_password@tcp(127.0.0.1:$mysql_port)/gobastion_mfa?charset=utf8mb4&parseTime=True&timeout=5s&readTimeout=10s&writeTimeout=10s" \
  "$test_dir/mfa.test" -test.run '^TestTOTPBackendIntegration$' -test.count=1 -test.timeout=180s -test.v
cleanup_fixture
echo 'PASS: MFA replay and shared-budget checks on SQLite, PostgreSQL and the MySQL dialect'
