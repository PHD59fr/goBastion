#!/bin/sh
# Disposable sshd integration test for DB-backed AuthorizedKeysCommand.
# Verifies: valid DB key accepted by sshd, user-writable authorized_keys ignored,
# revoked/disabled/expired key rejected, DB/bootstrap failure fails closed.
# Then exercises the real sudo/ForceCommand/bootstrap/session/MFA path.
set -eu

GO_BIN=${GO_BIN:-go}

image=alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
had_image=false
docker image inspect "$image" >/dev/null 2>&1 && had_image=true

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/gobastion-sshd-ak.XXXXXX")
seed_src=
container_id=
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$container_id" ] && docker container inspect "$container_id" >/dev/null 2>&1; then
    docker rm -fv "$container_id" >/dev/null 2>&1 || status=1
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

seed_src=$(mktemp -d "$repo_dir/scripts/.sshd-test-seed.XXXXXX")
cat > "$seed_src/main.go" << 'GO'
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
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
	mode := flag.String("mode", "valid", "valid|disabled|enabled|expired|delete|mfa|code|assert-session|assert-egress")
	privOut := flag.String("write-priv", "", "optional: generate keypair and write private key")
	pubOut := flag.String("write-pub", "", "optional: write generated public key")
	flag.Parse()
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
	case "mfa":
		secret, err := totp.GenerateSecret()
		must(err)
		ciphertext, err := cryptokey.Encrypt(secret)
		must(err)
		must(db.Model(&u).Updates(map[string]any{"totp_enabled": true, "totp_secret": ciphertext}).Error)
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
apk add --no-cache openssh-client openssh-keygen openssh-server sudo su-exec >/dev/null
ssh-keygen -A >/dev/null 2>&1
adduser -D -s /bin/sh testuser
passwd -u testuser >/dev/null 2>&1 || sed -i 's/^testuser:![^:]*:/testuser:*:/' /etc/shadow || true
mkdir -p /home/testuser/.ssh /run/gobastion /var/lib/goBastion /app
cp /mnt/goBastion /app/goBastion
chmod 755 /app/goBastion
# Transform the actual Alpine configuration with the image's build helper.
sh /mnt/configure-sshd.sh
: > /etc/ssh/banner
/usr/sbin/sshd -T > /tmp/sshd-effective.conf
grep -qx 'authorizedkeysfile none' /tmp/sshd-effective.conf
grep -qx 'authorizedkeyscommand /app/goBastion --authorizedKeys %u' /tmp/sshd-effective.conf
grep -qx 'authorizedkeyscommanduser root' /tmp/sshd-effective.conf
grep -qx 'forcecommand /usr/bin/sudo -n /usr/local/sbin/gobastion-session "$SSH_ORIGINAL_COMMAND"' /tmp/sshd-effective.conf
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
  kill "$(cat /run/sshd.pid)" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    echo "FAIL: $step" >&2
    for log in /tmp/product-*.out /tmp/product-*.err; do
      [ ! -f "$log" ] || tail -30 "$log" >&2
    done
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
chown root:gobastion /goBastion.log
chmod 0620 /goBastion.log
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
  timeout 20 ssh -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5 \
    -i /mnt/ssh/valid -- admin@127.0.0.1 "$@"
}
step=product-command
product_ssh '-osh accountInfo --user admin' > /tmp/product-info.out 2>/tmp/product-info.err
grep -q 'Username: admin' /tmp/product-info.out
echo "== real command error status =="
step=product-error-status
if product_ssh '-osh noSuchE2ECommand' > /tmp/product-invalid.out 2>/tmp/product-invalid.err; then
  echo 'unknown command unexpectedly succeeded' >&2; exit 1
else
  status=$?
  test "$status" -eq 1
fi
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
echo "== privileged reconciliation through real session =="
step=product-reconciliation
cat /mnt/ssh/valid.pub | product_ssh '-osh accountCreate --user producttarget' > /tmp/product-create.out 2>/tmp/product-create.err
grep -q "User 'producttarget' created successfully" /tmp/product-create.out
getent passwd producttarget >/dev/null
test -s /home/producttarget/.ssh/authorized_keys
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

echo "Running disposable sshd container..."
# Network is required to install openssh packages in the minimal Alpine image.
container_id=$(docker create --label gobastion.test=sshd-authorized-keys \
  --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add FSETID \
  --cap-add SETGID --cap-add SETUID --cap-add KILL --cap-add NET_BIND_SERVICE --cap-add SYS_CHROOT \
  --tmpfs /run:size=16m,mode=0755 --tmpfs /tmp:size=32m,mode=1777 \
  --tmpfs /var/lib/goBastion:size=32m,mode=0755 \
  --mount "type=bind,source=$test_dir/goBastion,target=/mnt/goBastion,readonly" \
  --mount "type=bind,source=$test_dir/seed,target=/mnt/seed,readonly" \
  --mount "type=bind,source=$repo_dir/scripts/configure-sshd.sh,target=/mnt/configure-sshd.sh,readonly" \
  --mount "type=bind,source=$repo_dir/scripts/sudo,target=/mnt/sudo,readonly" \
  --mount "type=bind,source=$test_dir/ssh,target=/mnt/ssh,readonly" \
  --mount "type=bind,source=$test_dir/run-tests.sh,target=/mnt/run-tests.sh,readonly" \
  --entrypoint /bin/sh "$image" /mnt/run-tests.sh)
docker start -a "$container_id"
status=$(docker inspect --format '{{.State.ExitCode}}' "$container_id")
test "$status" -eq 0
