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

{
  msg=$0
  gsub(/\r$/,"",msg)

  # defaults
  lvl=6
  ev=""
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
  # "Connection closed by authenticating user <user> <ip> port <p> [preauth]"
  # f[1]=Connection f[2]=closed f[3]=by f[4]=authenticating f[5]=user f[6]=USER f[7]=IP f[8]=port f[9]=PORT
  else if (msg ~ /^Connection closed by authenticating user /) {
    if (n >= 9) {
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
  else if (msg ~ /^Received disconnect from /) {
    for (i=1; i<=n; i++) {
      if (f[i] == "from" && i+1 <= n) from = f[i+1]
      if (f[i] == "port" && i+1 <= n) { port = port_clean(f[i+1]); break }
    }
    ev="disconnect"
  }
  # "Disconnected from authenticating user <user> <ip> port <p> [preauth]"
  # f[1]=Disconnected f[2]=from f[3]=authenticating f[4]=user f[5]=USER f[6]=IP f[7]=port f[8]=PORT
  else if (msg ~ /^Disconnected from authenticating user /) {
    if (n >= 8) {
      user=f[5]; from=f[6]; port=port_clean(f[8])
      ev="disconnect"
      lvl=4
    }
  }
  # "Disconnected from user <user> <ip> port <p>"
  # f[1]=Disconnected f[2]=from f[3]=user f[4]=USER f[5]=IP f[6]=port f[7]=PORT
  else if (msg ~ /^Disconnected from user /) {
    if (n >= 7) {
      user=f[4]; from=f[5]; port=port_clean(f[7])
      ev="disconnect"
    }
  }

  emit(msg, host, lvl, ev, from, port, user, to, fp)
}
' &

# Tail GELF app logs (goBastion events: logins, commands, errors).
tail -f /goBastion.log