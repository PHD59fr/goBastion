#!/bin/sh
set -eu
trap 's=$?;if [ "$s" != 0 ];then cat /tmp/pg.log /tmp/my.log 2>/dev/null || true;fi' EXIT
mkdir -p /tmp/pgdata /run/mysqld
chown postgres /tmp/pgdata
chown mysql /run/mysqld
su-exec postgres initdb -D /tmp/pgdata -A trust >/tmp/init.log
fixture_ip=$(hostname -i | awk '{print $1}')
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=db.fixture -addext "subjectAltName=DNS:db.fixture,IP:127.0.0.1,IP:::1,IP:$fixture_ip" -keyout /tmp/pgdata/server.key -out /tmp/pgdata/server.crt >/tmp/tls.log 2>&1
chown postgres /tmp/pgdata/server.key /tmp/pgdata/server.crt
chmod 0600 /tmp/pgdata/server.key
cat /tmp/pgdata/server.crt >> /opt/gobastion-db-root/etc/ssl/certs/ca-certificates.crt
cat /tmp/pgdata/server.crt >> /etc/ssl/certs/ca-certificates.crt
cp /tmp/pgdata/server.crt /tmp/db-server.crt
cp /tmp/pgdata/server.key /tmp/db-server.key
chown mysql /tmp/db-server.key
chmod 0600 /tmp/db-server.key
printf '127.0.0.1 db.fixture wrong.fixture\n' >> /etc/hosts
printf 'host all postgres 0.0.0.0/0 trust\n' >> /tmp/pgdata/pg_hba.conf
su-exec postgres pg_ctl -D /tmp/pgdata -o '-c ssl=on -c client_connection_check_interval=100ms -h 0.0.0.0,:: -p 55432 -k /tmp' -w start >/tmp/pg.log
mariadb-install-db --user=mysql --datadir=/tmp/mydata --auth-root-authentication-method=normal >/tmp/mysql-init.log
mariadbd --no-defaults --user=mysql --datadir=/tmp/mydata --port=53306 --bind-address=127.0.0.1 --socket=/run/mysqld/test.sock --ssl-cert=/tmp/db-server.crt --ssl-key=/tmp/db-server.key >/tmp/my.log 2>&1 &
redis-server --port 0 --tls-port 56379 --tls-cert-file /tmp/db-server.crt --tls-key-file /tmp/db-server.key --tls-auth-clients no --bind 127.0.0.1 --requirepass sandbox-secret --rename-command CONFIG HIDDENCONFIG --daemonize yes
# A restricted authenticated user must never RESET into the broader, passwordless
# default account. Also cover RESET renamed to the canonical name of a safe command.
for redis_port in 56380 56381; do
 if [ "$redis_port" = 56381 ]; then
  set -- --rename-command PING ORIGINALPING --rename-command RESET PING
 else
  set --
 fi
 redis-server --port 0 --tls-port "$redis_port" --tls-cert-file /tmp/db-server.crt --tls-key-file /tmp/db-server.key --tls-auth-clients no --bind 127.0.0.1 --pidfile "/tmp/redis-$redis_port.pid" --logfile "/tmp/redis-$redis_port.log" --daemonize yes "$@"
 redis_ready=no
 for attempt in $(seq 1 50); do
  if redis-cli --tls --cacert /tmp/db-server.crt -h 127.0.0.1 -p "$redis_port" ECHO READY >/dev/null 2>&1; then redis_ready=yes; break; fi
  sleep 0.1
 done
 [ "$redis_ready" = yes ] || { cat "/tmp/redis-$redis_port.log" >&2; exit 1; }
 redis-cli --tls --cacert /tmp/db-server.crt -h 127.0.0.1 -p "$redis_port" SET forbidden:key FORBIDDEN_DATA >/dev/null
 redis-cli --tls --cacert /tmp/db-server.crt -h 127.0.0.1 -p "$redis_port" ACL SETUSER limited on '>sandbox-secret' '~allowed:*' '+get' '+auth' '+reset' '+ping' '+echo' '+command' >/dev/null
done
mysql_ready=no
for attempt in $(seq 1 200); do
 if mariadb-admin --protocol=tcp -h127.0.0.1 -P53306 -uroot ping >/dev/null 2>&1; then mysql_ready=yes; break; fi
 sleep 0.1
done
[ "$mysql_ready" = yes ] || { echo 'FAIL: MariaDB fixture did not become ready' >&2; exit 1; }
psql -h127.0.0.1 -p55432 -Upostgres -dpostgres -c 'CREATE DATABASE policytest' >/dev/null
mariadb --protocol=tcp -h127.0.0.1 -P53306 -uroot -e 'CREATE DATABASE policytest'
mariadb --protocol=tcp -h127.0.0.1 -P53306 -uroot -e "CREATE USER 'credentialuser'@'127.0.0.1' IDENTIFIED BY 'sandbox-secret'"
GOB_POLICY_INTEGRATION=1 /policy.test -test.run 'TestConcurrentAdministratorRemoval|TestCommandLifecycleIntegration' -test.v
/recording.test -test.v
GOB_POLICY_INTEGRATION=1 /session.test -test.run '^TestLoginHistoryIntegration$' -test.v
psql -h127.0.0.1 -p55432 -Upostgres -dpostgres -c "CREATE ROLE credentialuser LOGIN PASSWORD 'sandbox-secret'" >/dev/null
printf 'host all credentialuser 127.0.0.1/32 scram-sha-256\nhost all credentialuser ::1/128 scram-sha-256\n' > /tmp/new-hba
cat /tmp/pgdata/pg_hba.conf >> /tmp/new-hba
cat /tmp/new-hba > /tmp/pgdata/pg_hba.conf
su-exec postgres pg_ctl -D /tmp/pgdata reload >/dev/null
if [ "${GOB_POLICY_ONLY:-}" != 1 ]; then
 # Existing OS accounts in the candidate UID range must never be killed.
 adduser -D -H -u 100000 reserveduid
 su-exec reserveduid sleep 120 &
 reserved_pid=$!
 # Match the production entrypoint's restrictive creation mask. In particular,
 # the session hosts file must remain readable by the mapped client UID.
 umask 0007
 GOB_SANDBOX_INTEGRATION=1 /dbsandbox.test -test.v
 # Also cover operators using an even stricter creation mask.
 (umask 0077; GOB_SANDBOX_INTEGRATION=1 /dbsandbox.test -test.run '^TestRealClients$' -test.v)
 /bin/sh /test-db-supervisor.sh
 kill -0 "$reserved_pid"
 kill "$reserved_pid"
 wait "$reserved_pid" 2>/dev/null || true
 echo 'PASS: existing OS account in sandbox UID range preserved' 
fi
