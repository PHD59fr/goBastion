#!/bin/sh
# Disposable sshd integration test for DB-backed AuthorizedKeysCommand.
# Verifies: valid DB key accepted by sshd, user-writable authorized_keys ignored,
# revoked/disabled/expired key rejected, DB/bootstrap failure fails closed.
# Then exercises the real sudo/ForceCommand/bootstrap/session/MFA path.
set -eu

GO_BIN=${GO_BIN:-go}
ttyrec_bin=${GOB_TEST_TTYREC_BIN:-}
external_enabled=${GOB_TEST_EXTERNAL_TARGET:-0}
case "$external_enabled" in 0|1) ;; *) echo 'GOB_TEST_EXTERNAL_TARGET must be 0 or 1' >&2; exit 2 ;; esac

image=alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
had_image=false
docker image inspect "$image" >/dev/null 2>&1 && had_image=true

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/gobastion-sshd-ak.XXXXXX")
seed_src=
container_id=
external_container_id=
external_network_id=
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$container_id" ] && docker container inspect "$container_id" >/dev/null 2>&1; then
    docker rm -fv "$container_id" >/dev/null 2>&1 || status=1
  fi
  if [ -n "$external_container_id" ] && docker container inspect "$external_container_id" >/dev/null 2>&1; then
    docker rm -fv "$external_container_id" >/dev/null 2>&1 || status=1
  fi
  if [ -n "$external_network_id" ] && docker network inspect "$external_network_id" >/dev/null 2>&1; then
    docker network rm "$external_network_id" >/dev/null 2>&1 || status=1
  fi
  if [ "$had_image" = false ] && docker image inspect "$image" >/dev/null 2>&1; then
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
  [ -z "$seed_src" ] || rm -rf "$seed_src"
  rm -rf "$test_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

recorded_enabled=0
if [ -n "$ttyrec_bin" ]; then
  test -x "$ttyrec_bin" || { echo "GOB_TEST_TTYREC_BIN must name an executable" >&2; exit 2; }
  cp "$ttyrec_bin" "$test_dir/ttyrec"
  recorded_enabled=1
else
  printf '#!/bin/sh\nexit 99\n' > "$test_dir/ttyrec"
fi
chmod 0755 "$test_dir/ttyrec"

seed_src=$(mktemp -d "$repo_dir/scripts/.sshd-test-seed.XXXXXX")
cat > "$seed_src/main.go" << 'GO'
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/totp"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	dbPath := flag.String("db", "", "sqlite path")
	user := flag.String("user", "", "username")
	pub := flag.String("pub", "", "authorized public key line")
	mode := flag.String("mode", "valid", "valid|disabled|enabled|expired|delete|mfa|code|password-mfa|password-clear|assert-session|assert-interactive|interactive-shell|assert-egress|egress-public|command-fixture|command-state|recording-off|recording-on|splash-off|splash-on")
	privOut := flag.String("write-priv", "", "optional: generate keypair and write private key")
	pubOut := flag.String("write-pub", "", "optional: write generated public key")
	sshKey := flag.String("ssh-key", "", "private key for the interactive-shell fixture client")
	flag.Parse()
	if *mode == "interactive-shell" {
		keyBytes, err := os.ReadFile(*sshKey)
		must(err)
		signer, err := ssh.ParsePrivateKey(keyBytes)
		must(err)
		hostKeyBytes, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
		must(err)
		hostKey, _, _, _, err := ssh.ParseAuthorizedKey(hostKeyBytes)
		must(err)
		client, err := ssh.Dial("tcp", "127.0.0.1:2223", &ssh.ClientConfig{
			User: *user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.FixedHostKey(hostKey),
			HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
			Timeout: 5 * time.Second,
		})
		must(err)
		defer client.Close()
		session, err := client.NewSession()
		must(err)
		defer session.Close()
		// A piped OpenSSH client advertises a zero-size terminal. Request
		// real dimensions so the product's go-prompt renderer can run.
		must(session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}))
		session.Stdin, session.Stdout, session.Stderr = os.Stdin, os.Stdout, os.Stderr
		must(session.Shell())
		must(session.Wait())
		return
	}
	if *privOut != "" && *pubOut != "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		priv, err := ssh.MarshalPrivateKey(key, "")
		must(err)
		must(os.WriteFile(*privOut, pem.EncodeToMemory(priv), 0600))
		spk, err := ssh.NewPublicKey(&key.PublicKey)
		must(err)
		must(os.WriteFile(*pubOut, ssh.MarshalAuthorizedKey(spk), 0644))
		return
	}
	if *dbPath == "" || *user == "" {
		must(fmt.Errorf("db and user required"))
	}
	db, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{})
	must(err)
	if *mode == "valid" || *mode == "disabled" || *mode == "enabled" || *mode == "expired" || *mode == "delete" {
		must(db.AutoMigrate(&models.User{}, &models.IngressKey{}))
	}
	var u models.User
	err = db.Where("username = ?", *user).First(&u).Error
	if err == gorm.ErrRecordNotFound {
		u = models.User{ID: uuid.New(), Username: *user, Role: models.RoleUser, Enabled: true}
		if *mode == "disabled" {
			u.Enabled = false
		}
		must(db.Select("ID", "Username", "Role", "Enabled", "SystemUser").Create(&u).Error)
		if *mode == "disabled" {
			must(db.Model(&u).Update("enabled", false).Error)
		}
	} else {
		must(err)
	}
	switch *mode {
	case "command-fixture":
		group := models.Group{Name: "command-e2e", MFARequired: true}
		must(db.Create(&group).Error)
		must(db.Create(&models.UserGroup{UserID: u.ID, GroupID: group.ID, Role: models.GroupRoleMember}).Error)
		must(db.Create(&models.DatabaseAlias{ResolveFrom: "command-e2e-db", Host: "existing.invalid", Port: 5432, Protocol: "postgres", GroupID: &group.ID}).Error)
		must(db.Create(&models.GroupGuestDBAccess{UserID: u.ID, GroupID: group.ID, Host: "existing.invalid", Port: 5432, Protocol: "postgres", Username: "reader"}).Error)
	case "command-state":
		// Include soft-deleted rows and all mutable fields in the affected
		// business tables. Login metadata and active-session rows change as
		// expected for each SSH attempt and are checked separately.
		var state struct {
			Groups      []models.Group
			Memberships []models.UserGroup
			Grants      []models.GroupGuestDBAccess
			Aliases     []models.DatabaseAlias
		}
		must(db.Unscoped().Order("id").Find(&state.Groups).Error)
		must(db.Unscoped().Order("id").Find(&state.Memberships).Error)
		must(db.Unscoped().Order("id").Find(&state.Grants).Error)
		must(db.Unscoped().Order("id").Find(&state.Aliases).Error)
		encoded, err := json.Marshal(state)
		must(err)
		// Compare digests so fixture credentials cannot reach test output.
		fmt.Printf("%x\n", sha256.Sum256(encoded))
	case "mfa":
		secret, err := totp.GenerateSecret()
		must(err)
		ciphertext, err := cryptokey.Encrypt(secret)
		must(err)
		must(db.Model(&u).Updates(map[string]any{"totp_enabled": true, "totp_secret": ciphertext}).Error)
	case "password-mfa":
		hash, err := bcrypt.GenerateFromPassword([]byte("E2E_SYNTHETIC_PASSWORD_ONLY_2026"), bcrypt.MinCost)
		must(err)
		must(db.Model(&u).Update("password_hash", string(hash)).Error)
	case "password-clear":
		must(db.Model(&u).Update("password_hash", "").Error)
	case "code":
		secret, err := cryptokey.Decrypt(u.TOTPSecret)
		must(err)
		code, err := totp.GenerateCode(secret, time.Now())
		must(err)
		// Consumed directly by ssh stdin; never print this mode's output in logs.
		fmt.Println(code)
	case "assert-session":
		var count int64
		must(db.Model(&models.ActiveSession{}).Count(&count).Error)
		if count != 0 || u.LastLoginAt.IsZero() || u.LastLoginFrom != "127.0.0.1" {
			must(fmt.Errorf("session cleanup or authenticated login metadata invalid"))
		}
	case "assert-interactive":
		var sessions []models.ActiveSession
		must(db.Find(&sessions).Error)
		if len(sessions) != 1 || sessions[0].Kind != "interactive_shell" || sessions[0].InstanceID != "sshd-e2e" || sessions[0].Username != u.Username || sessions[0].ProcessIdentity == "" || sessions[0].PID <= 0 {
			must(fmt.Errorf("interactive session registration invalid"))
		}
		fmt.Println(sessions[0].PID)
	case "assert-egress":
		var keys []models.SelfEgressKey
		must(db.Where("user_id = ?", u.ID).Find(&keys).Error)
		if len(keys) != 1 || !strings.HasPrefix(keys[0].PrivKey, "gob:v2:") {
			must(fmt.Errorf("encrypted egress key missing"))
		}
		plaintext, err := cryptokey.Decrypt(keys[0].PrivKey)
		must(err)
		_, err = ssh.ParsePrivateKey([]byte(plaintext))
		if err != nil {
			must(fmt.Errorf("stored egress key is invalid"))
		}
	case "egress-public":
		var keys []models.SelfEgressKey
		must(db.Where("user_id = ?", u.ID).Find(&keys).Error)
		if len(keys) != 1 || *pubOut == "" {
			must(fmt.Errorf("expected one egress key and a public-key output path"))
		}
		must(os.WriteFile(*pubOut, []byte(keys[0].PubKey+"\n"), 0644))
	case "recording-off", "recording-on", "splash-off", "splash-on":
		var instance models.BastionInstance
		must(db.Where("instance_id = ?", "sshd-e2e").First(&instance).Error)
		var cfg map[string]json.RawMessage
		must(json.Unmarshal([]byte(instance.Config), &cfg))
		if *mode == "splash-off" || *mode == "splash-on" {
			var splash map[string]json.RawMessage
			must(json.Unmarshal(cfg["splash"], &splash))
			if *mode == "splash-on" { splash["enabled"] = json.RawMessage("true") } else { splash["enabled"] = json.RawMessage("false") }
			splashJSON, err := json.Marshal(splash)
			must(err)
			cfg["splash"] = splashJSON
		} else {
			var recorder map[string]json.RawMessage
			must(json.Unmarshal(cfg["ttyrec"], &recorder))
			if *mode == "recording-off" { recorder["enabled"] = json.RawMessage("false") } else { recorder["enabled"] = json.RawMessage("true") }
			recordingJSON, err := json.Marshal(recorder)
			must(err)
			cfg["ttyrec"] = recordingJSON
		}
		updated, err := json.Marshal(cfg)
		must(err)
		must(db.Model(&instance).Update("config", string(updated)).Error)
	case "disabled":
		must(db.Model(&u).Update("enabled", false).Error)
	case "enabled":
		must(db.Model(&u).Update("enabled", true).Error)
	case "delete":
		must(db.Where("user_id = ?", u.ID).Delete(&models.IngressKey{}).Error)
	case "expired", "valid":
		if *pub == "" {
			b, err := os.ReadFile(*pubOut)
			if err == nil {
				*pub = string(b)
			} else {
				must(fmt.Errorf("pub required"))
			}
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*pub))
		must(err)
		ik := models.IngressKey{ID: uuid.New(), UserID: u.ID, Key: *pub, Type: parsed.Type(), Size: 2048, Fingerprint: ssh.FingerprintSHA256(parsed)}
		if *mode == "expired" {
			t := time.Now().Add(-time.Hour)
			ik.ExpiresAt = &t
		}
		must(db.Select("ID", "UserID", "Key", "Type", "Size", "Fingerprint", "ExpiresAt", "PIVAttested").Create(&ik).Error)
	}
}
GO

echo "Building goBastion and seed helper..."
CGO_ENABLED=0 "$GO_BIN" build -C "$repo_dir" -o "$test_dir/goBastion" ./cmd/goBastion
CGO_ENABLED=0 "$GO_BIN" build -C "$repo_dir" -o "$test_dir/audit-writer" ./cmd/audit-writer
CGO_ENABLED=0 "$GO_BIN" build -C "$repo_dir" -o "$test_dir/seed" "$seed_src"
rm -rf "$seed_src"
seed_src=

mkdir -p "$test_dir/ssh"
"$test_dir/seed" -write-priv "$test_dir/ssh/valid" -write-pub "$test_dir/ssh/valid.pub"
"$test_dir/seed" -write-priv "$test_dir/ssh/injected" -write-pub "$test_dir/ssh/injected.pub"
chmod 600 "$test_dir/ssh/valid" "$test_dir/ssh/injected"

cat > "$test_dir/run-tests.sh" << 'INNER'
#!/bin/sh
set -eu
apk add --no-cache openssh-client openssh-keygen openssh-server openssh-sftp-server rsync sudo su-exec >/dev/null
ssh-keygen -A >/dev/null 2>&1
adduser -D -s /bin/sh testuser
passwd -u testuser >/dev/null 2>&1 || sed -i 's/^testuser:![^:]*:/testuser:*:/' /etc/shadow || true
mkdir -p /home/testuser/.ssh /run/gobastion /var/lib/goBastion /app
cp /mnt/goBastion /app/goBastion
cp /mnt/audit-writer /app/audit-writer
chmod 755 /app/goBastion
chmod 700 /app/audit-writer
# Transform the actual Alpine configuration with the image's build helper.
sh /mnt/configure-sshd.sh
: > /etc/ssh/banner
/usr/sbin/sshd -T > /tmp/sshd-effective.conf
grep -qx 'authorizedkeysfile none' /tmp/sshd-effective.conf
grep -qx 'authorizedkeyscommand /app/goBastion --authorizedKeys %u' /tmp/sshd-effective.conf
grep -qx 'authorizedkeyscommanduser root' /tmp/sshd-effective.conf
grep -qx 'forcecommand /usr/bin/sudo -n /usr/local/sbin/gobastion-session "$SSH_ORIGINAL_COMMAND"' /tmp/sshd-effective.conf
grep -qx 'allowstreamlocalforwarding no' /tmp/sshd-effective.conf
grep -qx 'disableforwarding yes' /tmp/sshd-effective.conf
cat > /run/gobastion/db.conf << EOF
DB_DRIVER=sqlite
DB_DSN=/var/lib/goBastion/test.db
EOF
chmod 600 /run/gobastion/db.conf
cp /mnt/ssh/valid.pub /tmp/valid.pub
/mnt/seed -db /var/lib/goBastion/test.db -user testuser -pub "$(cat /tmp/valid.pub)" -mode valid
/usr/sbin/sshd -p 2222 -o ListenAddress=127.0.0.1 -o PidFile=/run/sshd.pid \
  -o PerSourcePenalties=no -o 'ForceCommand=/bin/echo AUTH_OK' -E /tmp/sshd.log
step=admission
finish() {
  status=$?
  trap - EXIT
  if [ -n "${audit_pid:-}" ]; then
    kill "$audit_pid" 2>/dev/null || true
    wait "$audit_pid" 2>/dev/null || true
  fi
  if [ -n "${revocation_client_pid:-}" ]; then
    kill "$revocation_client_pid" 2>/dev/null || true
  fi
  if [ -n "${interactive_client_pid:-}" ]; then
    kill "$interactive_client_pid" 2>/dev/null || true
  fi
  if [ -n "${password_client_pid:-}" ]; then
    kill "$password_client_pid" 2>/dev/null || true
  fi
  if [ -n "${term_recorder_pid:-}" ]; then
    kill "$term_recorder_pid" 2>/dev/null || true
  fi
  if [ -f /run/sshd-target.pid ]; then
    kill "$(cat /run/sshd-target.pid)" 2>/dev/null || true
  fi
  kill "$(cat /run/sshd.pid)" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    echo "FAIL: $step" >&2
    for log in /tmp/product-*.out /tmp/product-*.err; do
      case "$log" in /tmp/product-password-*) continue ;; esac
      [ ! -f "$log" ] || tail -30 "$log" >&2
    done
    for log in /tmp/rsync-*.err /tmp/scp-*.err /tmp/sftp-transfer.err /tmp/sftp-proxy-key.err; do
      [ ! -f "$log" ] || { echo "--- $log ---" >&2; tail -30 "$log" >&2; }
    done
    [ ! -f /tmp/transfer-argv ] || { echo '--- transfer remote shell argv ---' >&2; cat /tmp/transfer-argv >&2; }
  fi
  exit "$status"
}
trap finish EXIT

ssh_opts="-p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5 -v"
echo "== valid key =="
out=$(ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-valid.err || true)
if ! echo "$out" | grep -q AUTH_OK; then
  echo "--- ssh output ---"; echo "$out"
  echo "--- ssh stderr ---"; cat /tmp/ssh-valid.err || true
  echo "--- authorized_keys command test ---"; /app/goBastion --authorizedKeys testuser || true
  echo "--- sshd log ---"; tail -120 /tmp/sshd.log || true
  exit 1
fi

echo "== Unix socket forwarding denied without a session =="
if timeout 10 ssh $ssh_opts -o ExitOnForwardFailure=yes -i /mnt/ssh/valid \
  -N -R /tmp/gobastion-forbidden-forward.sock:/tmp/target.sock \
  testuser@127.0.0.1 >/tmp/ssh-streamlocal.out 2>/tmp/ssh-streamlocal.err; then
  echo "Unix socket forwarding unexpectedly accepted" >&2
  exit 1
fi
if ! grep -Eiq 'remote port forwarding failed|administratively prohibited|forwarding disabled' /tmp/ssh-streamlocal.err; then
  echo "Unix socket forwarding failure was not a forwarding refusal" >&2
  cat /tmp/ssh-streamlocal.err >&2
  exit 1
fi

echo "== injected authorized_keys ignored =="
mkdir -p /home/testuser/.ssh
cat /mnt/ssh/injected.pub > /home/testuser/.ssh/authorized_keys
chmod 700 /home/testuser/.ssh; chmod 600 /home/testuser/.ssh/authorized_keys
chown -R testuser:testuser /home/testuser/.ssh
if ssh $ssh_opts -i /mnt/ssh/injected testuser@127.0.0.1 2>/tmp/ssh-injected.err; then
  echo "injected key unexpectedly accepted" >&2; exit 1
fi

echo "== revoked key rejected =="
/mnt/seed -db /var/lib/goBastion/test.db -user testuser -mode delete
if ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-revoked.err; then
  echo "revoked key unexpectedly accepted" >&2; exit 1
fi

echo "== expired key rejected =="
/mnt/seed -db /var/lib/goBastion/test.db -user testuser -pub "$(cat /tmp/valid.pub)" -mode expired
if ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-expired.err; then
  echo "expired key unexpectedly accepted" >&2; exit 1
fi
/mnt/seed -db /var/lib/goBastion/test.db -user testuser -mode delete
/mnt/seed -db /var/lib/goBastion/test.db -user testuser -pub "$(cat /tmp/valid.pub)" -mode valid
ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-restored.err | grep -qx AUTH_OK

echo "== disabled user rejected =="
/mnt/seed -db /var/lib/goBastion/test.db -user testuser -mode disabled
if ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-disabled.err; then
  echo "disabled user unexpectedly accepted" >&2; exit 1
fi
/mnt/seed -db /var/lib/goBastion/test.db -user testuser -mode enabled
ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-enabled.err | grep -qx AUTH_OK

echo "== bootstrap failure fail-closed =="
mv /run/gobastion/db.conf /run/gobastion/db.conf.saved
if ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-bootstrapfail.err; then
  echo "bootstrap failure unexpectedly accepted" >&2; exit 1
fi
mv /run/gobastion/db.conf.saved /run/gobastion/db.conf
ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-bootstrap-restored.err | grep -qx AUTH_OK

echo "== DB failure fail-closed =="
cat > /run/gobastion/db.conf << EOF
DB_DRIVER=sqlite
DB_DSN=/definitely/missing/path/test.db
EOF
if ssh $ssh_opts -i /mnt/ssh/valid testuser@127.0.0.1 2>/tmp/ssh-dbfail.err; then
  echo "DB failure unexpectedly accepted" >&2; exit 1
fi

echo "ALL_SSHD_INGRESS_TESTS_PASSED"

echo "== real ForceCommand bootstrap =="
step=product-bootstrap
# Keep the admission scenarios above isolated from the fully migrated product DB.
export DB_DRIVER=sqlite DB_DSN=/var/lib/goBastion/product.db INSTANCE_ID=sshd-e2e
EGRESS_ENC_KEY=$(head -c 32 /dev/urandom | base64)
export EGRESS_ENC_KEY
addgroup -S gobastion
addgroup -S gobastion-auditors
mkdir -p /app/ttyrec /usr/local/sbin
chmod 0700 /run/gobastion
chown root:gobastion /var/lib/goBastion /app/ttyrec
chmod 2770 /var/lib/goBastion
chmod 0751 /app/ttyrec
touch /goBastion.log
chown root:root /goBastion.log
chmod 0600 /goBastion.log
/app/audit-writer > /tmp/audit-collector.out 2>&1 &
audit_pid=$!
audit_wait=0
while [ ! -S /run/gobastion-audit/audit.sock ]; do
  if ! kill -0 "$audit_pid" 2>/dev/null || [ "$audit_wait" -ge 50 ]; then
    echo 'audit collector failed to start' >&2
    exit 1
  fi
  audit_wait=$((audit_wait + 1))
  sleep 0.1
done
kill -0 "$audit_pid"
cp /mnt/sudo/gobastion-session.sh /usr/local/sbin/gobastion-session
cp /mnt/sudo/gobastion-sync-user.sh /usr/local/sbin/gobastion-sync-user
chmod 0755 /usr/local/sbin/gobastion-session /usr/local/sbin/gobastion-sync-user
cat > /etc/sudoers.d/gobastion-session <<'SUDOERS'
%gobastion ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-session *
%gobastion ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-sync-user *
Defaults!/usr/local/sbin/gobastion-session env_keep += "SSH_CLIENT SSH_CONNECTION SSH_TTY"
SUDOERS
chmod 0440 /etc/sudoers.d/gobastion-session
visudo -c >/dev/null
{
  printf 'DB_DRIVER=%s\nDB_DSN=%s\nINSTANCE_ID=%s\n' "$DB_DRIVER" "$DB_DSN" "$INSTANCE_ID"
  printf 'EGRESS_ENC_KEY=%s\n' "$EGRESS_ENC_KEY"
} > /run/gobastion/db.conf
chmod 0600 /run/gobastion/db.conf
printf 'admin\n%s\n' "$(cat /mnt/ssh/valid.pub)" | /app/goBastion --firstInstall > /tmp/product-bootstrap.out
grep -q 'created successfully as administrator' /tmp/product-bootstrap.out
kill "$(cat /run/sshd.pid)"
# Use another port so the previous listener cannot mask the production command.
/usr/sbin/sshd -p 2223 -o ListenAddress=127.0.0.1 -o PidFile=/run/sshd.pid \
  -o PerSourcePenalties=no -E /tmp/sshd-product.log
product_ssh() {
  timeout "${product_ssh_timeout:-20}" ssh -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5 \
    -i /mnt/ssh/valid -- admin@127.0.0.1 "$@"
}
product_ssh_tty() {
  timeout 20 ssh -tt -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5 \
    -i /mnt/ssh/valid -- admin@127.0.0.1 "$@"
}
wait_for_process_stop() {
  process_pid=$1
  process_name=$2
  for attempt in $(seq 1 50); do
    if [ ! -r "/proc/$process_pid/stat" ]; then return 0; fi
    process_state=$(cut -d ' ' -f 3 "/proc/$process_pid/stat")
    case "$process_state" in Z|X) return 0 ;; esac
    sleep 0.1
  done
  echo "$process_name process $process_pid survived actor revocation" >&2
  return 1
}
step=product-command
product_ssh '-osh accountInfo --user admin' > /tmp/product-info.out 2>/tmp/product-info.err
grep -q 'Username: admin' /tmp/product-info.out
echo "== DB request routed to root supervisor =="
step=product-db-supervisor-route
cat > /usr/local/sbin/gobastion-db-session <<'DB_SUPERVISOR'
#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ]
[ "${SUDO_USER:-}" = admin ]
[ "$#" -eq 2 ] && [ "$1" = target ] && [ "$2" = --pg ]
echo DB_SUPERVISOR_ROUTE_OK
exit 42
DB_SUPERVISOR
chmod 0700 /usr/local/sbin/gobastion-db-session
if product_ssh '--db target --pg' > /tmp/product-db-route.out 2>/tmp/product-db-route.err; then
  echo 'DB supervisor stub unexpectedly returned success' >&2; exit 1
else
  status=$?
  test "$status" -eq 42
fi
grep -qx DB_SUPERVISOR_ROUTE_OK /tmp/product-db-route.out
echo "== real command error status =="
step=product-error-status
if product_ssh '-osh noSuchE2ECommand' > /tmp/product-invalid.out 2>/tmp/product-invalid.err; then
  echo 'unknown command unexpectedly succeeded' >&2; exit 1
else
  status=$?
  test "$status" -eq 1
fi
echo "== invalid -osh commands preserve state and redact credentials =="
step=product-invalid-command-state-and-redaction
/mnt/seed -db "$DB_DSN" -user admin -mode command-fixture
/mnt/seed -db "$DB_DSN" -user admin -mode command-state > /tmp/osh-state.before
assert_osh_failure() {
  case_name=$1
  expected_redaction=$2
  shift 2
  log_start=$(wc -c < /goBastion.log)
  # Keep these captures outside finish's diagnostic glob: a redaction
  # regression must fail without copying a supplied secret into CI output.
  if product_ssh "$@" > /tmp/osh-error.out 2>/tmp/osh-error.err; then
    echo "invalid command unexpectedly succeeded: $case_name" >&2
    exit 1
  else
    command_status=$?
    if [ "$command_status" -ne 1 ]; then
      echo "invalid command returned unexpected status $command_status: $case_name" >&2
      exit 1
    fi
  fi
  /mnt/seed -db "$DB_DSN" -user admin -mode command-state > /tmp/osh-state.after
  if ! cmp -s /tmp/osh-state.before /tmp/osh-state.after; then
    echo "invalid command mutated group state: $case_name" >&2
    exit 1
  fi
  tail -c "+$((log_start + 1))" /goBastion.log > /tmp/osh-error.audit
  if ! grep -Fq '"msg":"command_failed"' /tmp/osh-error.audit; then
    echo "invalid command did not reach the command failure audit: $case_name" >&2
    exit 1
  fi
  grep -F '"msg":"command_failed"' /tmp/osh-error.audit > /tmp/osh-error.command-audit
  if ! grep -Eq '"_collector_uid":'"$(id -u admin)"'([,}])' /tmp/osh-error.command-audit; then
    echo "command failure was not collected with the authenticated Unix UID: $case_name" >&2
    exit 1
  fi
  if grep -Fq "$credential_marker" /tmp/osh-error.out /tmp/osh-error.err /goBastion.log /tmp/sshd-product.log; then
    echo "invalid command exposed a synthetic credential: $case_name" >&2
    exit 1
  fi
  if [ "$expected_redaction" = yes ] && ! grep -Fq '[REDACTED]' /tmp/osh-error.audit; then
    echo "credential-bearing command lacks a redacted audit value: $case_name" >&2
    exit 1
  fi
}
credential_marker=E2E_SYNTHETIC_CREDENTIAL_MUST_NOT_APPEAR
assert_osh_failure mfa-missing-arguments no '-osh groupSetMFA'
assert_osh_failure mfa-missing-policy no '-osh groupSetMFA --group command-e2e'
assert_osh_failure mfa-conflicting-policy no '-osh groupSetMFA --group command-e2e --required --optional'
assert_osh_failure guest-missing-arguments yes "-osh groupAddGuestDBAccess --password $credential_marker"
assert_osh_failure guest-wrong-role yes "-osh groupAddGuestDBAccess --group command-e2e --account admin --host db.invalid --user reader --protocol postgres --password=$credential_marker"
assert_osh_failure guest-invalid-port yes "-osh groupAddGuestDBAccess --group command-e2e --account admin --host db.invalid --user reader --protocol postgres --password $credential_marker --port invalid"
assert_osh_failure alias-missing-arguments no '-osh groupDelDBAlias'
assert_osh_failure alias-missing-id no '-osh groupDelDBAlias --group command-e2e'
assert_osh_failure alias-invalid-id no '-osh groupDelDBAlias --group command-e2e --id invalid'
/mnt/seed -db "$DB_DSN" -user admin -mode assert-session
rm -f /tmp/osh-error.out /tmp/osh-error.err /tmp/osh-error.audit /tmp/osh-state.before /tmp/osh-state.after
echo "== interactive shell command and normal cleanup =="
step=product-interactive-lifecycle
log_start=$(wc -c < /goBastion.log)
mkfifo /tmp/interactive-input
timeout 20 /mnt/seed -user admin -mode interactive-shell -ssh-key /mnt/ssh/valid \
  </tmp/interactive-input > /tmp/product-interactive.out 2>/tmp/product-interactive.err &
interactive_client_pid=$!
exec 7>/tmp/interactive-input
wait_for_interactive_output() {
  expected_output=$1
  for attempt in $(seq 1 50); do
    if grep -Fq "$expected_output" /tmp/product-interactive.out; then return 0; fi
    sleep 0.1
  done
  echo 'interactive shell did not produce its expected output' >&2
  return 1
}
# Wait for go-prompt's rendered prompt before writing keystrokes; sending
# input before terminal initialization can exercise only the tty echo.
wait_for_interactive_output 'admin@'
interactive_session_pid=$(/mnt/seed -db "$DB_DSN" -user admin -mode assert-interactive)
printf 'accountInfo --user admin' >&7
# go-prompt reads a byte batch at a time; keep Enter in a separate read.
wait_for_interactive_output 'accountInfo --user admin'
printf '\n' >&7
wait_for_interactive_output 'Username: admin'
printf 'exit' >&7
sleep 0.2
printf '\n' >&7
exec 7>&-
wait "$interactive_client_pid"
interactive_client_pid=
wait_for_process_stop "$interactive_session_pid" 'interactive session'
/mnt/seed -db "$DB_DSN" -user admin -mode assert-session
tail -c "+$((log_start + 1))" /goBastion.log > /tmp/product-interactive.audit
grep -Fq '"_cmd":"interactive"' /tmp/product-interactive.audit
grep -Fq '"_cmd":"accountInfo"' /tmp/product-interactive.audit
grep -Fq '"_reason":"exit"' /tmp/product-interactive.audit
rm -f /tmp/interactive-input
echo 'PASS: interactive shell command, normal exit, process termination and registry cleanup'
echo "== encrypted egress key via inherited bootstrap =="
step=product-egress
mkdir -p /usr/local/bin
cat > /usr/local/bin/ssh-keygen <<'KEYGEN'
#!/bin/sh
set -eu
if [ -n "${DB_DSN+x}${EGRESS_ENC_KEY+x}${EGRESS_ENC_KEYS+x}" ]; then
  echo 'child inherited bootstrap secret variables' >&2
  exit 1
fi
: > /home/admin/.keygen-env-checked
exec /usr/bin/ssh-keygen "$@"
KEYGEN
chmod 0755 /usr/local/bin/ssh-keygen
product_ssh '-osh selfGenerateEgressKey --type ed25519' > /tmp/product-egress.out 2>/tmp/product-egress.err
grep -q 'Egress key generated and stored' /tmp/product-egress.out
test -f /home/admin/.keygen-env-checked
/mnt/seed -db "$DB_DSN" -user admin -mode assert-egress
rm /usr/local/bin/ssh-keygen
echo "== established SSH transport and child stop after revocation =="
step=product-active-ssh-revocation
# Use a separate ordinary sshd so the target command can run without the
# bastion's ForceCommand. Disabling the account directly in the DB isolates
# the session actor monitor from privileged account reconciliation.
adduser -D -s /bin/sh targetlogin
passwd -u targetlogin >/dev/null 2>&1 || sed -i 's/^targetlogin:![^:]*:/targetlogin:*:/' /etc/shadow || true
mkdir -p /home/targetlogin/.ssh
/mnt/seed -db "$DB_DSN" -user admin -mode egress-public -write-pub /home/targetlogin/.ssh/authorized_keys
chown -R targetlogin:targetlogin /home/targetlogin/.ssh
chmod 0700 /home/targetlogin/.ssh
chmod 0600 /home/targetlogin/.ssh/authorized_keys
cat > /tmp/sshd-target.conf <<'TARGET_SSHD'
Port 2224
ListenAddress 127.0.0.1
PidFile /run/sshd-target.pid
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile .ssh/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers targetlogin
AllowTcpForwarding yes
Subsystem sftp /usr/lib/ssh/sftp-server
TARGET_SSHD
/usr/sbin/sshd -t -f /tmp/sshd-target.conf
/usr/sbin/sshd -f /tmp/sshd-target.conf -E /tmp/sshd-target.log
product_ssh '-osh selfAddAccess --server 127.0.0.1 --username targetlogin --port 2224 --force' > /tmp/product-target-access.out 2>/tmp/product-target-access.err
grep -q 'Personal access added successfully' /tmp/product-target-access.out
/mnt/seed -db "$DB_DSN" -user admin -mode recording-off
product_ssh_timeout=35
product_ssh 'targetlogin@127.0.0.1:2224 sleep 61' > /tmp/product-revocation.out 2>/tmp/product-revocation.err &
revocation_client_pid=$!
ready=no
for attempt in $(seq 1 100); do
  if pgrep -u admin -x ssh >/dev/null 2>&1 && pgrep -u targetlogin -f '^sleep 61$' >/dev/null 2>&1; then
    ready=yes; break
  fi
  if ! kill -0 "$revocation_client_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [ "$ready" != yes ]; then
  echo 'egress SSH command did not become active' >&2
  cat /tmp/product-revocation.out /tmp/product-revocation.err /tmp/sshd-target.log >&2
  exit 1
fi
egress_pid=$(pgrep -u admin -x ssh | head -1)
/mnt/seed -db "$DB_DSN" -user admin -mode disabled
stopped=no
for attempt in $(seq 1 100); do
  if ! kill -0 "$revocation_client_pid" 2>/dev/null; then stopped=yes; break; fi
  sleep 0.1
done
if [ "$stopped" != yes ]; then
  echo 'established SSH transport survived account revocation' >&2
  exit 1
fi
if wait "$revocation_client_pid"; then
  echo 'revoked SSH session unexpectedly succeeded' >&2
  exit 1
else
  status=$?
  if [ "$status" -ne 1 ]; then
    echo "revoked SSH session returned status $status, expected actor revocation status 1" >&2
    exit 1
  fi
fi
revocation_client_pid=
unset product_ssh_timeout
wait_for_process_stop "$egress_pid" 'direct SSH child'
/mnt/seed -db "$DB_DSN" -user admin -mode enabled
/mnt/seed -db "$DB_DSN" -user admin -mode assert-session
echo 'PASS: established SSH transport and direct child close after actor revocation'
if [ "$GOB_TEST_RECORDED" = 1 ]; then
echo "== recorded SSH transport and children stop after revocation =="
step=product-recorded-ssh-revocation
cp /mnt/ttyrec /usr/local/bin/ttyrec
test -x /usr/local/bin/ttyrec
/mnt/seed -db "$DB_DSN" -user admin -mode recording-on

live_test_pid() {
  for candidate in $(pgrep -u "$1" -x "$2" 2>/dev/null || true); do
    [ -r "/proc/$candidate/stat" ] || continue
    candidate_state=$(cut -d ' ' -f 3 "/proc/$candidate/stat")
    case "$candidate_state" in
      Z|X) ;;
      *) echo "$candidate"; return 0 ;;
    esac
  done
  return 1
}
product_ssh_timeout=35
# The real recorder opens a PTY; force a PTY on the outer SSH connection too.
timeout "$product_ssh_timeout" ssh -tt -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5 \
  -i /mnt/ssh/valid -- admin@127.0.0.1 'targetlogin@127.0.0.1:2224 sleep 62' \
  > /tmp/product-recorded-revocation.out 2>/tmp/product-recorded-revocation.err &
revocation_client_pid=$!
ready=no
for attempt in $(seq 1 100); do
  if recorder_pid=$(live_test_pid admin ttyrec) && \
    recorded_egress_pid=$(live_test_pid admin ssh) && \
    pgrep -u targetlogin -f '^sleep 62$' >/dev/null 2>&1; then
    ready=yes; break
  fi
  if ! kill -0 "$revocation_client_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [ "$ready" != yes ]; then
  echo 'recorded egress SSH command did not become active' >&2
  cat /tmp/product-recorded-revocation.out /tmp/product-recorded-revocation.err /tmp/sshd-target.log >&2
  exit 1
fi
/mnt/seed -db "$DB_DSN" -user admin -mode disabled
stopped=no
for attempt in $(seq 1 100); do
  if ! kill -0 "$revocation_client_pid" 2>/dev/null; then stopped=yes; break; fi
  sleep 0.1
done
if [ "$stopped" != yes ]; then
  echo 'recorded SSH transport survived account revocation' >&2
  exit 1
fi
if wait "$revocation_client_pid"; then
  echo 'revoked recorded SSH session unexpectedly succeeded' >&2
  exit 1
else
  status=$?
  if [ "$status" -ne 1 ]; then
    echo "revoked recorded SSH session returned status $status, expected actor revocation status 1" >&2
    exit 1
  fi
fi
revocation_client_pid=
unset product_ssh_timeout
wait_for_process_stop "$recorder_pid" 'ttyrec child'
wait_for_process_stop "$recorded_egress_pid" 'recorded SSH child'
recorders_stopped=no
for attempt in $(seq 1 50); do
  if ! live_test_pid admin ttyrec >/dev/null 2>&1; then recorders_stopped=yes; break; fi
  sleep 0.1
done
[ "$recorders_stopped" = yes ] || { echo 'a ttyrec descendant survived actor revocation' >&2; exit 1; }
spool_seen=no
for spool in /app/ttyrec/admin/127.0.0.1/.ssh-record-*; do
  [ -d "$spool" ] || continue
  [ -f "$spool/manifest.json" ] || { echo 'interrupted recording spool lacks its recovery manifest' >&2; exit 1; }
  spool_seen=yes
done
[ "$spool_seen" = yes ] || { echo 'interrupted recording spool was not retained' >&2; exit 1; }
/mnt/seed -db "$DB_DSN" -user admin -mode enabled
/mnt/seed -db "$DB_DSN" -user admin -mode assert-session
echo 'PASS: recorded SSH transport and children close; interrupted spool retains its recovery manifest'
echo '== recorder parent SIGTERM stops its child and command =='
step=recorder-parent-term
su-exec admin /usr/local/bin/ttyrec -T never -f /tmp/ttyrec-term.raw -- \
  /bin/sh -c 'echo $$ > /tmp/ttyrec-term-child.pid; exec /bin/sleep 63' \
  > /tmp/ttyrec-term.out 2>/tmp/ttyrec-term.err &
term_recorder_pid=$!
ready=no
for attempt in $(seq 1 100); do
  if [ -s /tmp/ttyrec-term-child.pid ]; then
    term_sleep_pid=$(cat /tmp/ttyrec-term-child.pid)
    if [ -r "/proc/$term_sleep_pid/stat" ]; then ready=yes; break; fi
  fi
  if ! kill -0 "$term_recorder_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
[ "$ready" = yes ] || { echo 'recorder command did not start' >&2; cat /tmp/ttyrec-term.err >&2; ps -o pid,ppid,user,comm,args >&2; exit 1; }
kill -TERM "$term_recorder_pid"
wait_for_process_stop "$term_recorder_pid" 'SIGTERM recorder parent'
wait "$term_recorder_pid" 2>/dev/null || true
term_recorder_pid=
wait_for_process_stop "$term_sleep_pid" 'SIGTERM recorder command'
recorders_stopped=no
for attempt in $(seq 1 50); do
  if ! live_test_pid admin ttyrec >/dev/null 2>&1; then recorders_stopped=yes; break; fi
  sleep 0.1
done
[ "$recorders_stopped" = yes ] || { echo 'a ttyrec child survived parent SIGTERM' >&2; exit 1; }
echo 'PASS: recorder SIGTERM closes its child and command'
else
  echo 'SKIP: recorded SSH revocation (set GOB_TEST_TTYREC_BIN to a built ttyrec executable)'
fi
echo "== real transfer payloads through ForceCommand =="
step=product-transfers
# rsync and legacy SCP invoke a remote shell. Bridge their server command into
# the bastion's documented target-prefixed ForceCommand syntax.
cat > /usr/local/bin/transfer-remote-shell <<'TRANSFER_SHELL'
#!/bin/sh
set -eu
printf '<%s>\n' "$@" > /tmp/transfer-argv
while [ "$#" -gt 0 ]; do
  case "$1" in rsync|scp|rsync\ *|scp\ *) break ;; esac
  shift
done
[ "$#" -gt 0 ] || exit 2
exec ssh -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes -o IdentitiesOnly=yes -i /mnt/ssh/valid \
  -- admin@127.0.0.1 "targetlogin@127.0.0.1:2224 $*"
TRANSFER_SHELL
chmod 0755 /usr/local/bin/transfer-remote-shell
printf 'goBastion transfer payload: rsync, SCP and SFTP\n' > /tmp/transfer-source
for splash in on off; do
  /mnt/seed -db "$DB_DSN" -user admin -mode "splash-$splash"
  rsync -e /usr/local/bin/transfer-remote-shell /tmp/transfer-source \
    targetlogin@target:/tmp/rsync-"$splash" 2>/tmp/rsync-"$splash".err
  cmp /tmp/transfer-source /tmp/rsync-"$splash"
done
# -O deliberately exercises the historical SCP server protocol, not SFTP.
scp -O -S /usr/local/bin/transfer-remote-shell /tmp/transfer-source \
  targetlogin@target:/tmp/scp-upload 2>/tmp/scp-upload.err
cmp /tmp/transfer-source /tmp/scp-upload
scp -O -S /usr/local/bin/transfer-remote-shell \
  targetlogin@target:/tmp/scp-upload /tmp/scp-download 2>/tmp/scp-download.err
cmp /tmp/transfer-source /tmp/scp-download
product_ssh '-osh bastionShowSFTPHostKey' > /tmp/sftp-proxy-key.out 2>/tmp/sftp-proxy-key.err
proxy_pubkey=$(grep -o 'ssh-ed25519 [A-Za-z0-9+/=]*' /tmp/sftp-proxy-key.out | head -1)
[ -n "$proxy_pubkey" ] || { echo 'SFTP proxy public key unavailable' >&2; exit 1; }
printf 'target-proxy %s\n' "$proxy_pubkey" > /tmp/sftp-proxy-known-hosts
cat > /tmp/sftp-commands <<'SFTP_COMMANDS'
put /tmp/transfer-source /tmp/sftp-upload
get /tmp/sftp-upload /tmp/sftp-download
SFTP_COMMANDS
sftp -b /tmp/sftp-commands -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/tmp/sftp-proxy-known-hosts \
  -o 'ProxyCommand=ssh -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -i /mnt/ssh/valid -- admin@127.0.0.1 "sftp-session targetlogin@[127.0.0.1]:2224"' \
  targetlogin@target-proxy > /tmp/sftp-transfer.out 2>/tmp/sftp-transfer.err
cmp /tmp/transfer-source /tmp/sftp-upload
cmp /tmp/transfer-source /tmp/sftp-download
echo 'PASS: rsync with splash on/off, legacy SCP upload/download, and pinned-host-key SFTP content'
echo '== native ProxyJump through an authorized target hop =='
step=product-proxyjump
product_ssh 'targetlogin@127.0.0.1:2224 --via targetlogin@127.0.0.1:2224 printf PROXYJUMP_OK' \
  > /tmp/product-proxyjump.out 2>/tmp/product-proxyjump.err
grep -q PROXYJUMP_OK /tmp/product-proxyjump.out
echo 'PASS: ProxyJump command reached the target through the hop'
if [ "$GOB_TEST_EXTERNAL_TARGET" = 1 ]; then
  echo '== SSH target in a separate Docker network namespace =='
  step=product-external-target
  external_ready=no
  for attempt in $(seq 1 100); do
    if ssh-keyscan -T 1 -p 2222 external-target >/dev/null 2>&1; then
      external_ready=yes; break
    fi
    sleep 0.1
  done
  [ "$external_ready" = yes ] || { echo 'external target sshd did not become ready' >&2; exit 1; }
  /mnt/seed -db "$DB_DSN" -user admin -mode egress-public \
    -write-pub /mnt/external-auth/authorized_keys
  product_ssh '-osh selfAddAccess --server external-target --username externaluser --port 2222 --force' \
    > /tmp/product-external-access.out 2>/tmp/product-external-access.err
  grep -Fq 'Personal access added successfully' /tmp/product-external-access.out
  product_ssh 'externaluser@external-target:2222 printf EXTERNAL_TARGET_OK' \
    > /tmp/product-external.out 2>/tmp/product-external.err
  grep -Fq 'EXTERNAL_TARGET_OK' /tmp/product-external.out
  /mnt/seed -db "$DB_DSN" -user admin -mode assert-session
  echo 'PASS: bastion reached a separate SSH target container by Docker DNS and bridge network'
fi
echo "== privileged reconciliation through real session =="
step=product-reconciliation
cat /mnt/ssh/valid.pub | product_ssh '-osh accountCreate --user producttarget' > /tmp/product-create.out 2>/tmp/product-create.err
grep -q "User 'producttarget' created successfully" /tmp/product-create.out
getent passwd producttarget >/dev/null
test -s /home/producttarget/.ssh/authorized_keys
echo "== password MFA rejects an invalid response and accepts the configured factor =="
step=product-password-mfa
/mnt/seed -db "$DB_DSN" -user admin -mode password-mfa
password_fixture=E2E_SYNTHETIC_PASSWORD_ONLY_2026
password_ssh_attempt() {
  attempt_name=$1
  factor=$2
  mkfifo /tmp/password-input
  product_ssh_tty '-osh accountInfo --user admin' < /tmp/password-input \
    > "/tmp/product-password-$attempt_name.out" 2> "/tmp/product-password-$attempt_name.err" &
  password_client_pid=$!
  exec 8>/tmp/password-input
  challenge_seen=no
  for attempt in $(seq 1 50); do
    if grep -Fq 'Enter password:' "/tmp/product-password-$attempt_name.out"; then
      challenge_seen=yes; break
    fi
    if ! kill -0 "$password_client_pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if [ "$challenge_seen" != yes ]; then
    echo "password MFA challenge did not appear: $attempt_name" >&2
    return 1
  fi
  # Allow ReadPassword to disable PTY echo after the prompt is written.
  sleep 0.1
  printf '%s\n' "$factor" >&8
  exec 8>&-
  if wait "$password_client_pid"; then
    attempt_status=0
  else
    attempt_status=$?
  fi
  password_client_pid=
  rm -f /tmp/password-input
  return "$attempt_status"
}
if password_ssh_attempt denied wrong-synthetic-password; then
  echo 'invalid password MFA response unexpectedly accepted' >&2; exit 1
else
  status=$?
  test "$status" -eq 1
fi
grep -Fq 'Invalid password' /tmp/product-password-denied.out
password_ssh_attempt accepted "$password_fixture"
grep -Fq 'Username: admin' /tmp/product-password-accepted.out
for output in /tmp/product-password-denied.out /tmp/product-password-denied.err \
  /tmp/product-password-accepted.out /tmp/product-password-accepted.err /goBastion.log /tmp/sshd-product.log; do
  if grep -Fq "$password_fixture" "$output"; then
    echo "synthetic password MFA factor appeared in $output" >&2; exit 1
  fi
done
/mnt/seed -db "$DB_DSN" -user admin -mode assert-session
/mnt/seed -db "$DB_DSN" -user admin -mode password-clear
unset password_fixture
echo 'PASS: password MFA rejected the wrong factor, accepted the right factor and kept it out of outputs and logs'
echo "== MFA missing response denied =="
step=product-mfa-denied
/mnt/seed -db "$DB_DSN" -user admin -mode mfa
if product_ssh '-osh accountInfo --user admin' </dev/null > /tmp/product-mfa-denied.out 2>/tmp/product-mfa-denied.err; then
  echo 'MFA EOF unexpectedly accepted' >&2; exit 1
else
  status=$?
  test "$status" -eq 1
fi
grep -q 'Could not read code' /tmp/product-mfa-denied.err
echo "== encrypted TOTP accepted =="
step=product-mfa-accepted
/mnt/seed -db "$DB_DSN" -user admin -mode code | product_ssh '-osh accountInfo --user admin' > /tmp/product-mfa.out 2>/tmp/product-mfa.err
grep -q 'Username: admin' /tmp/product-mfa.out
/mnt/seed -db "$DB_DSN" -user admin -mode assert-session
# The root-only bootstrap copy must not survive successful session startup.
test -z "$(find /run/gobastion -maxdepth 1 -name 'bootstrap.*' -print)"
echo "ALL_SSHD_FORCECOMMAND_TESTS_PASSED"
INNER
chmod +x "$test_dir/run-tests.sh"

if [ "$external_enabled" = 1 ]; then
  mkdir -m 0755 "$test_dir/external-auth"
  cat > "$test_dir/external-target.sh" <<'EXTERNAL_TARGET'
#!/bin/sh
set -eu
apk add --no-cache openssh-server openssh-keygen >/dev/null
ssh-keygen -A >/dev/null 2>&1
adduser -D -s /bin/sh externaluser
passwd -u externaluser >/dev/null 2>&1 || sed -i 's/^externaluser:![^:]*:/externaluser:*:/' /etc/shadow || true
mkdir -p /run/sshd
cat > /tmp/sshd-external.conf <<'SSHD_EXTERNAL'
Port 2222
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile /mnt/external-auth/authorized_keys
# Disposable bind-mounted public-key fixture has a host UID, not this container user.
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers externaluser
SSHD_EXTERNAL
/usr/sbin/sshd -t -f /tmp/sshd-external.conf
exec /usr/sbin/sshd -D -e -f /tmp/sshd-external.conf
EXTERNAL_TARGET
  chmod 0755 "$test_dir/external-target.sh"
  external_network_id=$(docker network create --label gobastion.test=sshd-external-target \
    "gobastion-sshd-$(basename "$test_dir")")
  external_container_id=$(docker create --label gobastion.test=sshd-external-target \
    --network "$external_network_id" --network-alias external-target \
    --tmpfs /run:size=8m,mode=0755 --tmpfs /tmp:size=16m,mode=1777 \
    --mount "type=bind,source=$test_dir/ssh,target=/mnt/ssh,readonly" \
    --mount "type=bind,source=$test_dir/external-auth,target=/mnt/external-auth,readonly" \
    --mount "type=bind,source=$test_dir/external-target.sh,target=/mnt/external-target.sh,readonly" \
    --entrypoint /bin/sh "$image" /mnt/external-target.sh)
  docker start "$external_container_id" >/dev/null
  set -- --network "$external_network_id" \
    --mount "type=bind,source=$test_dir/external-auth,target=/mnt/external-auth"
else
  set --
fi

echo "Running disposable sshd container..."
# Network is required to install openssh packages in the minimal Alpine image.
container_id=$(docker create --label gobastion.test=sshd-authorized-keys \
  "$@" \
  --env "GOB_TEST_RECORDED=$recorded_enabled" \
  --env "GOB_TEST_EXTERNAL_TARGET=$external_enabled" \
  --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add FSETID \
  --cap-add SETGID --cap-add SETUID --cap-add KILL --cap-add NET_BIND_SERVICE --cap-add SYS_CHROOT \
  --tmpfs /run:size=16m,mode=0755 --tmpfs /tmp:size=32m,mode=1777 \
  --tmpfs /var/lib/goBastion:size=32m,mode=0755 \
  --mount "type=bind,source=$test_dir/goBastion,target=/mnt/goBastion,readonly" \
  --mount "type=bind,source=$test_dir/audit-writer,target=/mnt/audit-writer,readonly" \
  --mount "type=bind,source=$test_dir/seed,target=/mnt/seed,readonly" \
  --mount "type=bind,source=$test_dir/ttyrec,target=/mnt/ttyrec,readonly" \
  --mount "type=bind,source=$repo_dir/scripts/configure-sshd.sh,target=/mnt/configure-sshd.sh,readonly" \
  --mount "type=bind,source=$repo_dir/scripts/sudo,target=/mnt/sudo,readonly" \
  --mount "type=bind,source=$test_dir/ssh,target=/mnt/ssh,readonly" \
  --mount "type=bind,source=$test_dir/run-tests.sh,target=/mnt/run-tests.sh,readonly" \
  --entrypoint /bin/sh "$image" /mnt/run-tests.sh)
docker start -a "$container_id"
status=$(docker inspect --format '{{.State.ExitCode}}' "$container_id")
test "$status" -eq 0
