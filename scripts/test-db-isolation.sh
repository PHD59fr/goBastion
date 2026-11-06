#!/bin/sh
set -eu
trap 's=$?;if [ "$s" != 0 ];then cat /tmp/pg.log /tmp/my.log 2>/dev/null || true;fi' EXIT
mkdir -p /tmp/pgdata /run/mysqld
chown postgres /tmp/pgdata
chown mysql /run/mysqld
su-exec postgres initdb -D /tmp/pgdata -A trust >/tmp/init.log
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=db.fixture -addext subjectAltName=DNS:db.fixture -keyout /tmp/pgdata/server.key -out /tmp/pgdata/server.crt >/tmp/tls.log 2>&1
chown postgres /tmp/pgdata/server.key /tmp/pgdata/server.crt
chmod 0600 /tmp/pgdata/server.key
cat /tmp/pgdata/server.crt >> /opt/gobastion-db-root/etc/ssl/certs/ca-certificates.crt
printf '127.0.0.1 db.fixture\n' >> /etc/hosts
printf 'host all postgres 0.0.0.0/0 trust\n' >> /tmp/pgdata/pg_hba.conf
su-exec postgres pg_ctl -D /tmp/pgdata -o '-c ssl=on -c client_connection_check_interval=100ms -h 0.0.0.0,:: -p 55432 -k /tmp' -w start >/tmp/pg.log
mariadb-install-db --user=mysql --datadir=/tmp/mydata --auth-root-authentication-method=normal >/tmp/mysql-init.log
mariadbd --no-defaults --user=mysql --datadir=/tmp/mydata --port=53306 --bind-address=127.0.0.1 --socket=/run/mysqld/test.sock >/tmp/my.log 2>&1 &
redis-server --port 56379 --bind 127.0.0.1 --requirepass sandbox-secret --daemonize yes
for attempt in $(seq 1 50); do if mariadb-admin --protocol=tcp -h127.0.0.1 -P53306 -uroot ping >/dev/null 2>&1; then break; fi; sleep 0.1; done
psql -h127.0.0.1 -p55432 -Upostgres -dpostgres -c 'CREATE DATABASE policytest' >/dev/null
mariadb --protocol=tcp -h127.0.0.1 -P53306 -uroot -e 'CREATE DATABASE policytest'
GOB_POLICY_INTEGRATION=1 /policy.test -test.run TestConcurrentAdministratorRemoval -test.v
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
 GOB_SANDBOX_INTEGRATION=1 /dbsandbox.test -test.v
 /bin/sh /test-db-supervisor.sh
 kill -0 "$reserved_pid"
 kill "$reserved_pid"
 wait "$reserved_pid" 2>/dev/null || true
 echo 'PASS: existing OS account in sandbox UID range preserved' 
fi
