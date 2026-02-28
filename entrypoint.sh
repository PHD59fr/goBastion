#!/bin/sh

# Auto startup: restores DB state if present.
# Exits 1 if no admin exists (no TTY) — retry every 5s until one is created via --firstInstall.
until /app/goBastion; do
    sleep 5
done

echo "[goBastion] Starting sshd..."
# -e sends sshd logs to stderr instead of syslog; 2>&1 forwards them to docker logs.
/usr/sbin/sshd -D -e 2>&1 &

# Tail GELF app logs (goBastion events: logins, commands, errors).
tail -f /goBastion.log
