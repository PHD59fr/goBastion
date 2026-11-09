#!/bin/sh
# Apply the same ingress configuration during image builds and integration tests.
set -eu
config=${1:-/etc/ssh/sshd_config}
config_dir=$(CDPATH= cd -- "$(dirname -- "$config")" && pwd)

# This helper configures the image at build time. Refuse operator Match blocks
# and populated Includes: OpenSSH can give their settings precedence over a
# global directive, or place appended directives inside a conditional block.
# Alpine's distributed Include is accepted only while its drop-in dir is empty.
if [ ! -f "$config" ] || [ -L "$config" ]; then
  echo "sshd configuration must be a regular file" >&2
  exit 1
fi
if ! awk -v default_include="$config_dir/sshd_config.d/*.conf" '
  /^[[:space:]]*(#|$)/ { next }
  {
    line = $0
    sub(/^[[:space:]]*/, "", line)
    count = split(line, fields, /[[:space:]=]+/)
    name = tolower(fields[1])
    if (index(name, "\"") != 0) exit 1
    if (name == "match") exit 1
    if (name == "include") {
      if (fields[2] != default_include || (count > 2 && fields[3] != "" && substr(fields[3], 1, 1) != "#")) exit 1
    }
  }
' "$config"; then
  echo "unsupported sshd Match or Include; review the image configuration" >&2
  exit 1
fi
for included in "$config_dir"/sshd_config.d/*.conf; do
  if [ -e "$included" ] || [ -L "$included" ]; then
    echo "sshd drop-in configuration requires explicit review" >&2
    exit 1
  fi
done

temporary=$(mktemp "$config.tmp.XXXXXXXXXX")
trap 'rm -f "$temporary"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cp -p "$config" "$temporary"
cat > "$temporary" <<'SSHD'
PermitRootLogin no
PasswordAuthentication no
LogLevel VERBOSE
SyslogFacility AUTH
AllowAgentForwarding no
AllowTcpForwarding no
PubkeyAuthentication yes
AuthorizedKeysFile none
AuthorizedKeysCommand /app/goBastion --authorizedKeys %u
AuthorizedKeysCommandUser root
Banner /etc/ssh/banner
ForceCommand /usr/bin/sudo -n /usr/local/sbin/gobastion-session "$SSH_ORIGINAL_COMMAND"
SSHD
awk '
  /^[[:space:]]*(#|$)/ { print; next }
  {
    line = $0
    sub(/^[[:space:]]*/, "", line)
    split(line, fields, /[[:space:]=]+/)
    name = tolower(fields[1])
    if (name ~ /^(permitrootlogin|passwordauthentication|loglevel|syslogfacility|allowagentforwarding|allowtcpforwarding|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|banner|forcecommand|subsystem)$/) next
    print
  }
' "$config" >> "$temporary"
mv "$temporary" "$config"
trap - EXIT HUP INT TERM
