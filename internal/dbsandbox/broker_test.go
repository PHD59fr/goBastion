package dbsandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
)

func TestMySQLAccountSwitchCannotReachDatabase(t *testing.T) {
	var wire, forwarded bytes.Buffer
	if err := writeMySQLPacket(&wire, 0, []byte{mysql.COM_CHANGE_USER, 'r', 'o', 'o', 't', 0}); err != nil {
		t.Fatal(err)
	}
	if err := copyMySQLCommands(&forwarded, &wire); err == nil || forwarded.Len() != 0 {
		t.Fatal("account-switch request reached database")
	}
	wire.Reset()
	if err := writeMySQLPacket(&wire, 0, append([]byte{mysql.COM_QUERY}, []byte("SELECT 1")...)); err != nil {
		t.Fatal(err)
	}
	want := wire.String()
	_ = copyMySQLCommands(&forwarded, &wire)
	if forwarded.String() != want {
		t.Fatal("ordinary SQL command was changed")
	}
}

func TestWorkerSpecificationNeverReceivesDatabasePasswords(t *testing.T) {
	for _, bin := range []string{"mariadb", "psql", "redis-cli"} {
		t.Run(bin, func(t *testing.T) {
			b, args, env := newBroker(context.Background(), "db.fixture", "127.0.0.1:1234", bin,
				[]string{"-h", "db.fixture", "-u", "alice"}, []string{"MYSQL_PWD=MYSQL_SENTINEL", "PGPASSWORD=PG_SENTINEL", "REDISCLI_AUTH=REDIS_SENTINEL", "LANG=C.UTF-8"}, nil)
			if b.password == "" {
				t.Fatal("broker did not retain its own credential")
			}
			encoded, err := json.Marshal(Spec{Binary: bin, Args: args, Env: env, IP: "127.0.0.1", Port: 1234})
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"MYSQL_PWD", "PGPASSWORD", "REDISCLI_AUTH", "SENTINEL"} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("credential leaked into worker specification: %s", encoded)
				}
			}
		})
	}
}

func TestRedisAdministrativeCommandsCannotReachDatabase(t *testing.T) {
	allowed := map[string]bool{"get": true, "config": false, "renamedconfig": false}
	for _, name := range []string{"CONFIG", "renamedconfig", "unknown"} {
		var wire, forwarded bytes.Buffer
		if err := writeRedisCommand(&wire, name, "GET", "requirepass"); err != nil {
			t.Fatal(err)
		}
		if err := copyRedisCommands(&forwarded, bufio.NewReader(&wire), allowed); err == nil || forwarded.Len() != 0 {
			t.Fatalf("administrative request was forwarded: %v: %s", err, forwarded.Bytes())
		}
	}
	var wire, forwarded bytes.Buffer
	if err := writeRedisCommand(&wire, "GET", "allowed-key"); err != nil {
		t.Fatal(err)
	}
	want := wire.String()
	_ = copyRedisCommands(&forwarded, bufio.NewReader(&wire), allowed)
	if forwarded.String() != want {
		t.Fatalf("regular command changed: %q", forwarded.String())
	}
	if !redisAdmin(redisValue{children: []redisValue{{text: []byte("renamedconfig")}, {children: []redisValue{{text: []byte("admin")}}}}}) {
		t.Fatal("renamed administrative command not detected")
	}
}

func TestMySQLLoginRejectsUnsupportedWireCapabilities(t *testing.T) {
	for n := 0; n < 33; n++ {
		if _, _, err := mysqlLogin(make([]byte, n)); err == nil {
			t.Fatalf("accepted malformed login of length %d", n)
		}
	}
	if _, _, err := mysqlLogin([]byte(strings.Repeat("x", 64))); err == nil {
		t.Fatal("accepted unsupported capabilities")
	}
}

func TestRealClientsRejectUntrustedServerName(t *testing.T) {
	if testing.Short() {
		t.Skip("integration fixture")
	}
	if os.Getenv("GOB_SANDBOX_INTEGRATION") != "1" {
		t.Skip("requires isolation-test fixture")
	}
	for _, bin := range []string{"mariadb", "psql", "redis-cli"} {
		t.Run(bin, func(t *testing.T) { testRejectedTLSName(t, bin) })
	}
}

func testRejectedTLSName(t *testing.T, bin string) {
	t.Helper()
	port := int64(55432)
	args := []string{"-X", "-h", "wrong.fixture", "-p", "55432", "-U", "credentialuser", "-d", "postgres"}
	env := []string{"PGPASSWORD=sandbox-secret"}
	input := "SELECT 1;\n"
	if bin == "mariadb" {
		port = 53306
		args = []string{"--protocol=tcp", "-h", "wrong.fixture", "-P", "53306", "-u", "root"}
		env = nil
	}
	if bin == "redis-cli" {
		port = 56379
		args = []string{"-h", "wrong.fixture", "-p", "56379"}
		env = []string{"REDISCLI_AUTH=sandbox-secret"}
		input = "PING\n"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, cleanup, err := Command(ctx, "wrong.fixture", port, bin, args, env)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	redisRejected := bin == "redis-cli" && strings.Contains(string(out), "ERR Upstream verified TLS") && !strings.Contains(string(out), "PONG")
	if (err == nil && !redisRejected) || ctx.Err() != nil {
		t.Fatalf("invalid server identity was not rejected promptly: %v / %v: %s", err, ctx.Err(), out)
	}
}

func TestRealRedisDoesNotExposeCredentialsThroughAdministrativeAliases(t *testing.T) {
	if os.Getenv("GOB_SANDBOX_INTEGRATION") != "1" {
		t.Skip("requires isolation-test fixture")
	}
	for _, command := range []string{"CONFIG GET requirepass", "HIDDENCONFIG GET requirepass", "ACL GETUSER default", "AUTH default replacement", "HELLO 3 AUTH default replacement"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd, cleanup, err := Command(ctx, "127.0.0.1", 56379, "redis-cli", []string{"-h", "127.0.0.1", "-p", "56379"}, []string{"REDISCLI_AUTH=sandbox-secret"})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		cmd.Stdin = strings.NewReader("PING\n" + command + "\n")
		out, _ := cmd.CombinedOutput()
		expired := ctx.Err() != nil
		cleanup()
		cancel()
		closed := strings.Contains(string(out), "Server closed") || strings.Contains(string(out), "ERR Upstream verified TLS")
		if expired || !closed || !strings.Contains(string(out), "PONG") || strings.Contains(string(out), "sandbox-secret") || strings.Contains(string(out), "requirepass\n") {
			t.Fatalf("credential command was not blocked: %s: %s", command, out)
		}
	}
}
