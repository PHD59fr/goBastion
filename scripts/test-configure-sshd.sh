#!/bin/sh
# Deterministic, unprivileged tests of the image's SSH configuration transform.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/gobastion-sshd-config.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
config=$test_dir/sshd_config

cat > "$config" <<'SSHD'
#AuthorizedKeysFile .ssh/commented
AuthorizedKeysFile .ssh/authorized_keys
  authorizedkeyscommand /bin/echo old
AUTHORIZEDKEYSCOMMANDUSER nobody
ForceCommand /bin/sh
ForceCommand=/bin/sh
PermitRootLogin yes
PasswordAuthentication yes
AllowAgentForwarding yes
AllowTcpForwarding yes
PubkeyAuthentication no
Subsystem sftp /bin/sh
ClientAliveInterval 25
#Match User commented
SSHD
sh "$repo_dir/scripts/configure-sshd.sh" "$config"
for expected in \
  'AuthorizedKeysFile none' \
  'AuthorizedKeysCommand /app/goBastion --authorizedKeys %u' \
  'AuthorizedKeysCommandUser root' \
  'ForceCommand /usr/bin/sudo -n /usr/local/sbin/gobastion-session "$SSH_ORIGINAL_COMMAND"' \
  'PermitRootLogin no' 'PasswordAuthentication no' \
  'AllowAgentForwarding no' 'AllowTcpForwarding no' 'PubkeyAuthentication yes' \
  'ClientAliveInterval 25'; do
  grep -Fqx "$expected" "$config"
done
if grep -Eq '^([^#]*old|[[:space:]]*Subsystem[[:space:]])' "$config"; then
  echo "conflicting active SSH directive survived" >&2
  exit 1
fi
cp "$config" "$test_dir/once"
sh "$repo_dir/scripts/configure-sshd.sh" "$config"
cmp "$config" "$test_dir/once"

# The stock Alpine Include has no packaged drop-in files.
mkdir "$test_dir/sshd_config.d"
printf 'Include %s/sshd_config.d/*.conf\n' "$test_dir" > "$config"
sh "$repo_dir/scripts/configure-sshd.sh" "$config"
grep -Fqx 'AuthorizedKeysFile none' "$config"

expect_rejection() {
  cp "$config" "$test_dir/before"
  if sh "$repo_dir/scripts/configure-sshd.sh" "$config" 2> "$test_dir/error"; then
    echo "unsafe SSH configuration accepted" >&2
    exit 1
  fi
  cmp "$config" "$test_dir/before"
}

printf 'Match User limited\n    X11Forwarding no\n' > "$config"
expect_rejection
printf 'mAtCh all\n    AuthorizedKeysFile /tmp/other-keys\n' > "$config"
expect_rejection
printf 'Match=User alice\n    AuthorizedKeysFile /tmp/other-keys\n' > "$config"
expect_rejection
printf '"Match" User alice\n    AuthorizedKeysFile /tmp/other-keys\n' > "$config"
expect_rejection
printf '\rMatch\r User alice\n    AuthorizedKeysFile /tmp/other-keys\n' > "$config"
expect_rejection
printf 'Include /uncontrolled/*.conf\n' > "$config"
expect_rejection
printf 'Include=/uncontrolled/*.conf\n' > "$config"
expect_rejection
printf 'Include %s/sshd_config.d/*.conf /uncontrolled/*.conf\n' "$test_dir" > "$config"
expect_rejection
printf 'Include %s/sshd_config.d/*.conf\n' "$test_dir" > "$config"
printf 'Match User alice\n    AuthorizedKeysFile /tmp/other-keys\n' > "$test_dir/sshd_config.d/override.conf"
expect_rejection

echo 'PASS: SSH directives, empty stock Include, conditional rejection, atomic refusal'
