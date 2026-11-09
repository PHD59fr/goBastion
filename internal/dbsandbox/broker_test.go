package dbsandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func TestRedisAuthenticationSelectsExplicitIdentityWithoutPassword(t *testing.T) {
	for _, tc := range []struct {
		name     string
		user     string
		password string
		want     []string
		explicit bool
	}{
		{name: "no identity", want: nil, explicit: false},
		{name: "default password only", password: "secret", want: []string{"AUTH", "secret"}, explicit: true},
		{name: "explicit nopass user", user: "reader", want: []string{"AUTH", "reader", ""}, explicit: true},
		{name: "explicit default nopass", user: "default", want: []string{"AUTH", "default", ""}, explicit: true},
		{name: "explicit user with password", user: "reader", password: "secret", want: []string{"AUTH", "reader", "secret"}, explicit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, explicit := redisAuthCommand(tc.user, tc.password)
			if explicit != tc.explicit {
				t.Fatalf("explicit = %v, want %v", explicit, tc.explicit)
			}
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("command = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedisInitialDatabaseSelection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		database string
		want     []string
		explicit bool
		valid    bool
	}{
		{name: "server default", database: "", explicit: false, valid: true},
		{name: "database zero", database: "0", want: []string{"SELECT", "0"}, explicit: true, valid: true},
		{name: "database two", database: "2", want: []string{"SELECT", "2"}, explicit: true, valid: true},
		{name: "canonical index", database: "02", want: []string{"SELECT", "2"}, explicit: true, valid: true},
		{name: "negative index", database: "-1", valid: false},
		{name: "non-numeric index", database: "cache", valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, explicit, err := redisSelectCommand(tc.database)
			if (err == nil) != tc.valid {
				t.Fatalf("redisSelectCommand(%q) error = %v, valid = %v", tc.database, err, tc.valid)
			}
			if !tc.valid {
				return
			}
			if explicit != tc.explicit || strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("redisSelectCommand(%q) = %q, %v; want %q, %v", tc.database, got, explicit, tc.want, tc.explicit)
			}
		})
	}

	b, args, _ := newBroker(context.Background(), "db.fixture", "127.0.0.1:6379", "redis-cli",
		[]string{"-h", "db.fixture", "-p", "6379", "-n", "2"}, nil, nil)
	if b.database != "2" {
		t.Fatalf("broker database = %q, want 2", b.database)
	}
	if strings.Join(args, " ") != "-e -h db.fixture -p 6379 -n 2" {
		t.Fatalf("unexpected redis client arguments: %q", args)
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

func TestRedisIdentityCommandsAndAliasesAreDenied(t *testing.T) {
	metadata := func(name, flag string) redisValue {
		return redisValue{children: []redisValue{{text: []byte(name)}, {text: []byte("1")}, {children: []redisValue{{text: []byte(flag)}}}}}
	}
	for _, tc := range []struct{ name, target, flag string }{
		{"reset", "reset", "no_auth"},
		{"auth", "auth", "no_auth"},
		{"ping", "reset", "no_auth"},
		{"get", "auth", "no_auth"},
		{"get", "config", "admin"},
	} {
		if redisCommandAllowed(tc.name, metadata(tc.target, tc.flag)) {
			t.Fatalf("identity or administrative command allowed: %s -> %s", tc.name, tc.target)
		}
	}
	if !redisCommandAllowed("get", metadata("get", "readonly")) {
		t.Fatal("ordinary GET was denied")
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
	for _, command := range []string{"CONFIG GET requirepass", "HIDDENCONFIG GET requirepass", "ACL GETUSER default", "AUTH default replacement", "HELLO 3 AUTH default replacement", "RESET"} {
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

func TestRealRedisResetCannotRestoreDefaultPrivileges(t *testing.T) {
	if os.Getenv("GOB_SANDBOX_INTEGRATION") != "1" {
		t.Skip("requires isolation-test fixture")
	}
	for _, tc := range []struct {
		port    int64
		command string
	}{{56380, "RESET"}, {56381, "PING"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		args := []string{"-h", "127.0.0.1", "-p", fmt.Sprint(tc.port), "--user", "limited"}
		cmd, cleanup, err := Command(ctx, "127.0.0.1", tc.port, "redis-cli", args, []string{"REDISCLI_AUTH=sandbox-secret"})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		cmd.Stdin = strings.NewReader("ECHO CONNECTED\nGET forbidden:key\n" + tc.command + "\nGET forbidden:key\n")
		out, _ := cmd.CombinedOutput()
		expired := ctx.Err() != nil
		cleanup()
		cancel()
		if expired || !strings.Contains(string(out), "CONNECTED") || !strings.Contains(string(out), "NOPERM") || strings.Contains(string(out), "FORBIDDEN_DATA") {
			t.Fatalf("Redis identity changed or fixture did not authenticate: port=%d: %s", tc.port, out)
		}
		if !strings.Contains(string(out), "Server closed") {
			t.Fatalf("identity command did not close session: %s", out)
		}
	}
}
