#!/bin/sh
set -eu
umask 0007

# ── Signal handling ──────────────────────────────────────────────────────────
# When docker stop sends SIGTERM, clean up background processes and stop sshd.
TAIL_PID=""
SYNC_PID=""
SSHD_PID=""
AWK_PID=""
SSHD_LOG_PIPE="/run/gobastion/sshd.log"

cleanup() {
	status=${1:-0}
	trap - TERM INT EXIT
  printf '{"version":"1.1","host":"%s","timestamp":%s,"level":6,"short_message":"shutting down","_mode":"system","_event":"shutdown"}\n' \
    "${HOSTNAME:-goBastion}" "$(date +%s)"
	[ -z "$SSHD_PID" ] || kill -TERM "$SSHD_PID" 2>/dev/null || true
	[ -z "$SYNC_PID" ] || kill "$SYNC_PID" 2>/dev/null || true
	[ -z "$TAIL_PID" ] || kill "$TAIL_PID" 2>/dev/null || true
	[ -z "$AWK_PID" ] || kill "$AWK_PID" 2>/dev/null || true
	[ -z "$SSHD_PID" ] || wait "$SSHD_PID" 2>/dev/null || true
	[ -z "$SYNC_PID" ] || wait "$SYNC_PID" 2>/dev/null || true
	[ -z "$TAIL_PID" ] || wait "$TAIL_PID" 2>/dev/null || true
	[ -z "$AWK_PID" ] || wait "$AWK_PID" 2>/dev/null || true
	rm -f "$SSHD_LOG_PIPE"
	exit "$status"
}
trap 'cleanup 143' TERM
trap 'cleanup 130' INT
trap 'cleanup $?' EXIT

# ── Config ───────────────────────────────────────────────────────────────────
# Write bootstrap secrets for the root-only ForceCommand wrapper. It forwards
# them in the application's environment, then drops to the connected user.
mkdir -p /run/gobastion
chmod 700 /run/gobastion
{
  [ -z "${DB_DRIVER:-}" ] || printf 'DB_DRIVER=%s\n' "$DB_DRIVER"
  [ -z "${DB_DSN:-}" ] || printf 'DB_DSN=%s\n' "$DB_DSN"
  [ -z "${EGRESS_ENC_KEY:-}" ] || printf 'EGRESS_ENC_KEY=%s\n' "$EGRESS_ENC_KEY"
  [ -z "${INSTANCE_ID:-}" ] || printf 'INSTANCE_ID=%s\n' "$INSTANCE_ID"
} > /run/gobastion/db.conf
# Only the small sudo session/sync wrappers read this file. The application
# itself runs as the connected user and receives these values via its private
# process environment.
chmod 600 /run/gobastion/db.conf

SYNC_INTERVAL="${SYNC_INTERVAL_SECONDS:-300}"
if ! printf '%s' "$SYNC_INTERVAL" | grep -Eq '^[1-9][0-9]*$'; then
	echo "SYNC_INTERVAL_SECONDS must be a positive integer" >&2
	exit 2
fi

# Reconcile permissions for persisted volumes and accounts created by older
# images. Members need DB/log/recording access, but never direct secret access.
chown root:gobastion /goBastion.log /var/lib/goBastion /app/ttyrec
chmod 0620 /goBastion.log
chmod 2770 /var/lib/goBastion /app/ttyrec
find /var/lib/goBastion -type d -exec chmod 2770 {} \;
find /var/lib/goBastion -type d -exec chgrp gobastion {} \;
find /var/lib/goBastion -type f -exec chgrp gobastion {} \;
find /var/lib/goBastion -type f -exec chmod 0660 {} \;
find /app/ttyrec -type d -exec chgrp gobastion {} \;
find /app/ttyrec -type d -exec chmod 2770 {} \;
find /app/ttyrec -type f -exec chgrp gobastion {} \;
find /app/ttyrec -type f -exec chmod 0640 {} \;
for home_dir in /home/*; do
	[ -d "$home_dir" ] || continue
	account=${home_dir##*/}
	if printf '%s' "$account" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,31}$'; then
		addgroup "$account" gobastion >/dev/null 2>&1 || true
	fi
done

# ── Log tail ─────────────────────────────────────────────────────────────────
# Tail GELF app logs immediately so docker logs captures startup events
# (DB connect, migrations, no-admin warnings) before sshd even starts.
touch /goBastion.log
tail -f /goBastion.log &
TAIL_PID=$!

# ── First install ────────────────────────────────────────────────────────────
# Auto startup: syncs DB state to OS if present.
# Exits 3 if no admin exists (no TTY) — waits until one is created via --firstInstall.
while true; do
	set +e
	/app/goBastion
	startup_status=$?
	set -e
	[ "$startup_status" -ne 0 ] || break
	if [ "$startup_status" -ne 3 ]; then
		printf '{"version":"1.1","host":"%s","timestamp":%s,"level":3,"short_message":"startup failed","_mode":"system","_event":"startup_failed","_exit_code":%s}\n' \
		  "${HOSTNAME:-goBastion}" "$(date +%s)" "$startup_status"
		exit "$startup_status"
	fi
    printf '{"version":"1.1","host":"%s","timestamp":%s,"level":4,"short_message":"Waiting for first admin. Run: docker exec -it %s /app/goBastion --firstInstall","_mode":"system","_event":"first_install_required"}\n' \
      "${HOSTNAME:-goBastion}" "$(date +%s)" "${HOSTNAME:-goBastion}"
    sleep 5
done

# SQLite may create its main file with 0644 independently of the umask. The
# root bootstrap has finished, so normalize it before accepting SSH sessions.
find /var/lib/goBastion -type f -exec chgrp gobastion {} \;
find /var/lib/goBastion -type f -exec chmod 0660 {} \;

# ── Periodic sync ────────────────────────────────────────────────────────────
# Enforce DB as source of truth at configurable intervals.
# Logs drift (rogue users, key changes) and corrects it automatically.
# Override with SYNC_INTERVAL_SECONDS env var (default: 300 = 5 minutes).
(while true; do
    sleep "$SYNC_INTERVAL"
    /app/goBastion --sync
done) &
SYNC_PID=$!

# ── sshd ─────────────────────────────────────────────────────────────────────
printf '{"version":"1.1","host":"%s","timestamp":%s,"level":6,"short_message":"starting sshd","_mode":"system","_event":"sshd_start"}\n' \
  "${HOSTNAME:-goBastion}" "$(date +%s)"

# -e sends sshd logs to stderr instead of syslog. A FIFO lets PID 1 track
# sshd and the formatter independently, preserving sshd's real exit status.
rm -f "$SSHD_LOG_PIPE"
mkfifo -m 0600 "$SSHD_LOG_PIPE"
awk '
function esc(s,    t){ t=s; gsub(/\\/,"\\\\",t); gsub(/"/,"\\\"",t); gsub(/\r/,"",t); return t }

function emit(msg, host, lvl, ev, from, port, user, to, fp,    now, out, ts, Y,M,D,h,m,s,d,z,era,doe,yoe,doy,mp,t){
  now = systime()
  if (now == _last_ts) { _seq++ } else { _last_ts = now; _seq = 0 }
  ts = now + _seq/10000
  # Compute ISO 8601 time from unix timestamp (no strftime in busybox awk)
  s = now % 60; t = int(now / 60)
  m = t % 60;   t = int(t / 60)
  h = t % 24;   d = int(t / 24)
  z = d + 719468; era = int(z / 146097)
  doe = z - era * 146097
  yoe = int((doe - int(doe/1460) + int(doe/36524) - int(doe/146096)) / 365)
  Y = yoe + era * 400
  doy = doe - (365*yoe + int(yoe/4) - int(yoe/100))
  mp = int((5*doy + 2) / 153)
  D = doy - int((153*mp + 2) / 5) + 1
  M = (mp < 10) ? mp + 3 : mp - 9
  Y = (M <= 2) ? Y + 1 : Y
  out = "{"
  out = out "\"version\":\"1.1\""
  out = out ",\"host\":\"" esc(host) "\""
  out = out ",\"short_message\":\"" esc(msg) "\""
  out = out ",\"timestamp\":" ts
  out = out ",\"level\":" lvl
  out = out ",\"msg\":\"" esc(msg) "\""
  out = out sprintf(",\"time\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\"", Y, M, D, h, m, s)
  out = out ",\"_mode\":\"ssh\""
  if (ev  != "") out = out ",\"_event\":\"" esc(ev) "\""
  if (from!= "") out = out ",\"_from\":\"" esc(from) "\""
  if (to  != "") out = out ",\"_to\":\"" esc(to) "\""
  if (port!= "") out = out ",\"_port\":" port
  if (user!= "") out = out ",\"_user\":\"" esc(user) "\""
  if (fp  != "") out = out ",\"_fingerprint\":\"" esc(fp) "\""
  out = out "}"
  print out
  fflush()
}

function extract_fp(s,    tmp){
  if (match(s, /SHA256:[A-Za-z0-9+\/=]+/)) {
    return substr(s, RSTART, RLENGTH)
  }
  return ""
}

function port_clean(p,    x){
  # "57852:11:" -> "57852"
  split(p, x, ":")
  return x[1]
}

BEGIN {
  host = (ENVIRON["HOSTNAME"] != "" ? ENVIRON["HOSTNAME"] : "goBastion")
}

function split_msgs(chunk, arr,    ns) {
  # Insert newline before known sshd message starters when mid-line.
  while (match(chunk, /[^ \t\r\n][ \t]+(Connection from |Starting session:|User child is on pid |Accepted publickey for |Postponed publickey for |Failed password for |Failed publickey for |Invalid user |Connection closed by |Received disconnect from |Disconnected from |Timeout before authentication for connection from |srclimit_penalise: )/)) {
    chunk = substr(chunk, 1, RSTART-1) "\n" substr(chunk, RSTART+1)
  }
  ns = split(chunk, arr, "\n")
  return ns
}

function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }

{
  raw = $0
  gsub(/\r$/, "", raw)

  # Split multi-message sshd chunks into separate lines.
  n_chunks = split_msgs(raw, chunks)
  for (ci = 1; ci <= n_chunks; ci++) {
    msg = trim(chunks[ci])
    if (msg == "") continue

    # defaults
    lvl=6; ev=""
    from=""; port=""; user=""; to=""; fp=""

    # tokenize (space-separated, POSIX-compatible)
    n = split(msg, f, /[[:space:]]+/)

    # --- Listen ---
    if (msg ~ /^Server listening on /) {
      ev="listen"
    }

    # --- Connection ---
    # "Connection from <ip> port <p> on <to> port <p2> [rdomain ...]"
    # f[1]=Connection f[2]=from f[3]=IP f[4]=port f[5]=PORT f[6]=on f[7]=TO
    else if (msg ~ /^Connection from /) {
      if (n >= 7) {
        from = f[3]
        port = port_clean(f[5])
        to   = f[7]
        ev="connect"
      }
    }

    # --- Auth attempts / success ---
    # "Postponed publickey for <user> from <ip> port <p> ..."
    # f[1]=Postponed f[2]=publickey f[3]=for f[4]=USER f[5]=from f[6]=IP f[7]=port f[8]=PORT
    else if (msg ~ /^Postponed publickey for /) {
      if (n >= 8) {
        user=f[4]; from=f[6]; port=port_clean(f[8])
        ev="auth_attempt"
      }
    }
    # "Accepted publickey for <user> from <ip> port <p> ..."
    else if (msg ~ /^Accepted publickey for /) {
      if (n >= 8) {
        user=f[4]; from=f[6]; port=port_clean(f[8])
        ev="auth_success"
        fp=extract_fp(msg)
      }
    }
    else if (msg ~ /^Accepted key /) {
      fp=extract_fp(msg)
      ev="key_seen"
    }

    # --- Session start ---
    else if (msg ~ /^Starting session:/) {
      for (i=1; i<=n; i++) {
        if (f[i] == "for"  && i+1 <= n) user = f[i+1]
        if (f[i] == "from" && i+1 <= n) from = f[i+1]
        if (f[i] == "port" && i+1 <= n) { port = port_clean(f[i+1]); break }
      }
      ev="session_start"
    }

    # --- Failures / abuse ---
    # "Failed publickey for root from 1.2.3.4 port 12345 ..."
    # "Failed publickey for invalid user bob from 1.2.3.4 port 12345 ..."
    else if (msg ~ /^Failed (password|publickey) for /) {
      if (f[4] == "invalid" && f[5] == "user") {
        user = f[6]
      } else {
        user = f[4]
      }
      for (i=1; i<=n; i++) {
        if (f[i] == "from" && i+1 <= n) from = f[i+1]
        if (f[i] == "port" && i+1 <= n) { port = port_clean(f[i+1]); break }
      }
      ev="auth_failed"
      lvl=4
      fp=extract_fp(msg)
    }
    # "Invalid user <user> from <ip> port <p>"
    else if (msg ~ /^Invalid user /) {
      user=f[3]
      for (i=1; i<=n; i++) {
        if (f[i] == "from" && i+1 <= n) from = f[i+1]
        if (f[i] == "port" && i+1 <= n) { port = port_clean(f[i+1]); break }
      }
      ev="invalid_user"
      lvl=4
    }
    # "Connection closed by invalid user <user> <ip> port <p> [preauth]"
    # f[1]=Connection f[2]=closed f[3]=by f[4]=invalid f[5]=user f[6]=USER f[7]=IP f[8]=port f[9]=PORT
    else if (msg ~ /^Connection closed by invalid user /) {
      if (n >= 8) {
        user=f[6]; from=f[7]; port=port_clean(f[9])
        ev="closed"
        lvl=4
      }
    }
    # "Connection closed by authenticating user <user> <ip> port <p> [preauth]"
    # f[1]=Connection f[2]=closed f[3]=by f[4]=authenticating f[5]=user f[6]=USER f[7]=IP f[8]=port f[9]=PORT
    else if (msg ~ /^Connection closed by authenticating user /) {
      if (n >= 8) {
        user=f[6]; from=f[7]; port=port_clean(f[9])
        ev="closed"
        lvl=4
      }
    }
    # "Connection closed by <ip> port <p> [preauth]"
    else if (msg ~ /^Connection closed by /) {
      for (i=1; i<=n; i++) {
        if (f[i] == "by"   && i+1 <= n) from = f[i+1]
        if (f[i] == "port" && i+1 <= n) { port = port_clean(f[i+1]); break }
      }
      ev="closed"
      lvl=4
    }
    # "Timeout before authentication for connection from <ip> to <ip>, pid = ..."
    else if (msg ~ /^Timeout before authentication for connection from /) {
      for (i=1; i<=n; i++) {
        if (f[i] == "from" && i+1 <= n) from = f[i+1]
        if (f[i] == "to"   && i+1 <= n) to   = f[i+1]
      }
      ev="timeout"
      lvl=4
    }
    # "srclimit_penalise: ipv4: new <ip>/<mask> deferred penalty ..."
    else if (msg ~ /^srclimit_penalise:/) {
      for (i=1; i<=n; i++) {
        if (f[i] == "new" && i+1 <= n) {
          split(f[i+1], z, "/")
          from = z[1]
          break
        }
      }
      ev="rate_limit"
      lvl=4
    }

    # --- Disconnects ---
    # "Received disconnect from <ip> port <p>:11: ..."
    # This is always paired with a "Disconnected from [user|invalid user] X" line — we
    # emit only this one to avoid duplicates. It carries IP+port; the username was already
    # logged in the auth_success / auth_failed event above.
    else if (msg ~ /^Received disconnect from /) {
      for (i=1; i<=n; i++) {
        if (f[i] == "from" && i+1 <= n) from = f[i+1]
        if (f[i] == "port" && i+1 <= n) { port = port_clean(f[i+1]); break }
      }
      ev="disconnect"
    }
    # "Disconnected from authenticating user <user> <ip> port <p> [preauth]"
    # Emitted when auth fails before a session is established (no Received disconnect pair).
    # f[1]=Disconnected f[2]=from f[3]=authenticating f[4]=user f[5]=USER f[6]=IP f[7]=port f[8]=PORT
    else if (msg ~ /^Disconnected from authenticating user /) {
      if (n >= 8) {
        user=f[5]; from=f[6]; port=port_clean(f[8])
        ev="disconnect"
        lvl=4
      }
    }
    # "Disconnected from user <user> <ip> port <p>" — always paired with Received disconnect; skip.
    # "Disconnected from invalid user <user> <ip> port <p>" — same; skip.
    else if (msg ~ /^Disconnected from (user |invalid user )/) {
      continue
    }

    emit(msg, host, lvl, ev, from, port, user, to, fp)
  }
}
' < "$SSHD_LOG_PIPE" &
AWK_PID=$!

/usr/sbin/sshd -D -e > "$SSHD_LOG_PIPE" 2>&1 &
SSHD_PID=$!
set +e
wait "$SSHD_PID"
sshd_status=$?
set -e
SSHD_PID=""
wait "$AWK_PID" 2>/dev/null || true
AWK_PID=""
cleanup "$sshd_status"
