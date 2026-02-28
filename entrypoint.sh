#!/bin/sh

# Auto startup: restores DB state if present.
# Exits 1 if no admin exists (no TTY) — retry every 5s until one is created via --firstInstall.
until /app/goBastion; do
    sleep 5
done

echo "[goBastion] Starting sshd..."
# -e sends sshd logs to stderr instead of syslog; 2>&1 forwards them to docker logs.
/usr/sbin/sshd -D -e 2>&1 \
| sed -r '
  # If sshd writes multiple messages in one chunk, split them back into separate lines.
  # Insert a newline BEFORE known message starters when they are not at start-of-line.
  s/([^\n])([[:space:]]+)(Connection from )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Starting session:)/\1\n\3/g;
  s/([^\n])([[:space:]]+)(User child is on pid )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Accepted publickey for )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Postponed publickey for )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Failed (password|publickey) for )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Invalid user )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Connection closed by )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Received disconnect from )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Disconnected from )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(Timeout before authentication for connection from )/\1\n\3/g;
  s/([^\n])([[:space:]]+)(srclimit_penalise: )/\1\n\3/g;
' \
| awk '
function esc(s,    t){ t=s; gsub(/\\/,"\\\\",t); gsub(/"/,"\\\"",t); gsub(/\r/,"",t); return t }

function emit(msg, host, lvl, ev, from, port, user, to, fp,    ts, out){
  ts = systime()
  out = "{"
  out = out "\"version\":\"1.1\""
  out = out ",\"host\":\"" esc(host) "\""
  out = out ",\"timestamp\":" ts
  out = out ",\"level\":" lvl
  out = out ",\"short_message\":\"" esc(msg) "\""
  out = out ",\"_mode\":\"ssh\""
  if (ev  != "") out = out ",\"_event\":\"" esc(ev) "\""
  if (from!= "") out = out ",\"_from\":\"" esc(from) "\""
  if (to  != "") out = out ",\"_to\":\"" esc(to) "\""
  if (port!= "") out = out ",\"_port\":" port
  if (user!= "") out = out ",\"_user\":\"" esc(user) "\""
  if (fp  != "") out = out ",\"_fingerprint\":\"" esc(fp) "\""
  out = out "}"
  print out
}

BEGIN {
  host = (ENVIRON["HOSTNAME"] != "" ? ENVIRON["HOSTNAME"] : "goBastion")
}

{
  msg=$0
  gsub(/\r$/,"",msg)

  # defaults
  lvl=6
  ev=""
  from=""; port=""; user=""; to=""; fp=""

  # --- Connection / listen ---
  if (match(msg, /^Server listening on /)) {
    ev="listen"
  }
  else if (match(msg, /^Connection from ([0-9.]+) port ([0-9]+) on ([0-9.]+) port ([0-9]+)/, a)) {
    from=a[1]; port=a[2]; to=a[3]
    ev="connect"
  }

  # --- Auth attempts / success ---
  else if (match(msg, /^Postponed publickey for ([^ ]+) from ([0-9.]+) port ([0-9]+)/, a)) {
    user=a[1]; from=a[2]; port=a[3]
    ev="auth_attempt"
  }
  else if (match(msg, /^Accepted publickey for ([^ ]+) from ([0-9.]+) port ([0-9]+)/, a)) {
    user=a[1]; from=a[2]; port=a[3]
    ev="auth_success"
    if (match(msg, /(SHA256:[A-Za-z0-9+\/=]+)/, f)) fp=f[1]
  }
  else if (match(msg, /^Accepted key [^ ]+ (SHA256:[A-Za-z0-9+\/=]+)/, f)) {
    # no ip/user/port in this line
    fp=f[1]
    ev="key_seen"
  }

  # --- Session start ---
  else if (match(msg, /^Starting session:.* for ([^ ]+) from ([0-9.]+) port ([0-9]+)/, a)) {
    user=a[1]; from=a[2]; port=a[3]
    ev="session_start"
  }

  # --- Failures / abuse ---
  else if (match(msg, /^Failed (password|publickey) for (invalid user )?([^ ]+) from ([0-9.]+) port ([0-9]+)/, a)) {
    user=a[3]; from=a[4]; port=a[5]
    ev="auth_failed"
    lvl=4
  }
  else if (match(msg, /^Invalid user ([^ ]+) from ([0-9.]+) port ([0-9]+)/, a)) {
    user=a[1]; from=a[2]; port=a[3]
    ev="invalid_user"
    lvl=4
  }
  else if (match(msg, /^Connection closed by ([0-9.]+) port ([0-9]+)( \[preauth\])?/, a)) {
    from=a[1]; port=a[2]
    ev="closed"
    lvl=4
  }
  else if (match(msg, /^Timeout before authentication for connection from ([0-9.]+) to ([0-9.]+), pid = ([0-9]+)/, a)) {
    from=a[1]; to=a[2]
    ev="timeout"
    lvl=4
  }
  else if (match(msg, /^srclimit_penalise: (ipv4|ipv6): new ([0-9.]+)\/[0-9]+ deferred penalty/, a)) {
    from=a[2]
    ev="rate_limit"
    lvl=4
  }

  # --- Disconnects ---
  else if (match(msg, /^Received disconnect from ([0-9.]+) port ([0-9]+)/, a)) {
    from=a[1]; port=a[2]
    ev="disconnect"
  }
  else if (match(msg, /^Disconnected from user ([^ ]+) ([0-9.]+) port ([0-9]+)/, a)) {
    user=a[1]; from=a[2]; port=a[3]
    ev="disconnect"
  }
  else if (match(msg, /^Disconnected from authenticating user ([^ ]+) ([0-9.]+) port ([0-9]+)/, a)) {
    user=a[1]; from=a[2]; port=a[3]
    ev="disconnect"
    lvl=4
  }

  emit(msg, host, lvl, ev, from, port, user, to, fp)
}
' &

# Tail GELF app logs (goBastion events: logins, commands, errors).
tail -f /goBastion.log
