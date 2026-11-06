package dbsandbox

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRealClients(t *testing.T) {
	if os.Getenv("GOB_SANDBOX_INTEGRATION") != "1" {
		t.Skip("requires the isolation-test Docker target")
	}
	if err := os.WriteFile("/var/lib/goBastion/private-marker", []byte("BASTION_SECRET"), 0660); err != nil {
		t.Fatal(err)
	}
	remote := routableTestHost(t)
	cases := []struct {
		binary, host string
		port         int64
		args         []string
		input        string
		env, wants   []string
	}{
		{"psql", "127.0.0.1", 55432, []string{"-X", "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", "-d", "postgres"},
			"SELECT 'SQL_OK';\n\\connect postgres\nSELECT 'RECONNECT_OK';\n\\! nc -w 1 127.0.0.1 56379 </dev/null || echo NETWORK_ISOLATED\n\\! test ! -e /app/goBastion && test ! -e /usr/local/sbin/gobastion-db-session && test ! -e /var/lib/goBastion/private-marker && test ! -e /run/gobastion/db.conf && echo FILES_ISOLATED\n\\! test ! -r /proc/1/mem && echo BROKER_PROTECTED\n\\! GOB_CHECK_CLIENT_CAPS=1 /bin/caps-test -test.run TestNativeCapabilities -test.v\n\\q\n", nil, []string{"SQL_OK", "RECONNECT_OK", "NETWORK_ISOLATED", "FILES_ISOLATED", "BROKER_PROTECTED", "CAPABILITIES_EMPTY"}},
		{"psql", remote, 55432, []string{"-X", "-h", remote, "-p", "55432", "-U", "postgres", "-d", "postgres"}, "SELECT 'ROUTABLE_OK';\n\\q\n", nil, []string{"ROUTABLE_OK"}},
		{"psql", "::1", 55432, []string{"-X", "-h", "::1", "-p", "55432", "-U", "postgres", "-d", "postgres"}, "SELECT 'IPV6_OK';\n\\q\n", nil, []string{"IPV6_OK"}},
		{"psql", "db.fixture", 55432, []string{"-X", "-h", "db.fixture", "-p", "55432", "-U", "credentialuser", "-d", "postgres"}, "SELECT 'TLS_AUTH_OK';\n\\q\n", []string{"PGPASSWORD=sandbox-secret", "PGSSLMODE=verify-full", "PGSSLROOTCERT=/etc/ssl/cert.pem"}, []string{"TLS_AUTH_OK"}},
		{"mariadb", "127.0.0.1", 53306, []string{"--protocol=tcp", "-h", "127.0.0.1", "-P", "53306", "-u", "root"}, "SELECT 'SQL_OK';\n", nil, []string{"SQL_OK"}},
		{"redis-cli", "127.0.0.1", 56379, []string{"-h", "127.0.0.1", "-p", "56379"}, "PING\n", []string{"REDISCLI_AUTH=sandbox-secret"}, []string{"PONG"}},
	}
	for _, tc := range cases {
		t.Run(tc.binary+tc.host, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd, clean, err := Command(ctx, tc.host, tc.port, tc.binary, clientTestArgs(tc.binary, tc.args), tc.env)
			if err != nil {
				t.Fatal(err)
			}
			defer clean()
			cmd.Stdin = strings.NewReader(tc.input)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("client: %v\n%s", err, out)
			}
			for _, want := range tc.wants {
				if !strings.Contains(string(out), want) {
					t.Fatalf("missing %q: %s", want, out)
				}
			}
		})
	}
}

func TestRejectArbitraryClient(t *testing.T) {
	if os.Getenv("GOB_SANDBOX_INTEGRATION") != "1" {
		t.Skip("root sandbox fixture required")
	}
	_, clean, err := Command(context.Background(), "127.0.0.1", 55432, "sh", nil, nil)
	if err == nil {
		clean()
		t.Fatal("arbitrary executable accepted")
	}
}

func TestRecordingAndCancellation(t *testing.T) {
	if os.Getenv("GOB_SANDBOX_INTEGRATION") != "1" {
		t.Skip("requires Docker fixtures")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := clientTestArgs("psql", []string{"-X", "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", "-d", "postgres"})
	sandbox, clean, err := Command(ctx, "127.0.0.1", 55432, "psql", args, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clean()
	recording := filepath.Join(t.TempDir(), "session.ttyrec")
	recorderArgs := append([]string{"-f", recording, "--", sandbox.Path}, sandbox.Args[1:]...)
	cmd := exec.CommandContext(ctx, "/usr/local/bin/ttyrec", recorderArgs...)
	cmd.Env, cmd.ExtraFiles = sandbox.Env, sandbox.ExtraFiles
	// Input echo cannot produce the concatenated result marker.
	cmd.Stdin = strings.NewReader("SELECT 'RECORDED_' || 'SQL';\n\\q\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("recorded client: %v: %s", err, out)
	}
	content, err := os.ReadFile(recording)
	if err != nil || !strings.Contains(string(content), "RECORDED_SQL") {
		t.Fatalf("missing recorded result: %v: %s", err, content)
	}

	limited, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	child, cleanup, err := Command(limited, "127.0.0.1", 55432, "psql", args, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	child.Stdin = strings.NewReader("\\! sleep 60\n")
	start := time.Now()
	if output, err := child.CombinedOutput(); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("cancellation failed: %v: %s", err, output)
	}
}

// The broker has no destination field, even when its peer sends hostile data.
func TestRelayReconnectsOnlyToPinnedDestination(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for i := 0; i < 3; i++ {
			conn, e := l.Accept()
			if e != nil {
				return
			}
			_, _ = io.WriteString(conn, "PINNED")
			_ = conn.Close()
		}
	}()
	first, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	parent, peer := os.NewFile(uintptr(pair[0]), "broker"), os.NewFile(uintptr(pair[1]), "client")
	defer func() { _ = peer.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); serve(ctx, parent, first, l.Addr().String()) }()
	for i := 0; i < 3; i++ {
		if _, err := peer.Write([]byte("127.0.0.1:1 ignored destination")); err != nil {
			t.Fatal(err)
		}
		data, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
		_, n, _, _, err := unix.Recvmsg(int(peer.Fd()), data, oob, unix.MSG_CMSG_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		messages, err := unix.ParseSocketControlMessage(oob[:n])
		if err != nil || len(messages) != 1 {
			t.Fatalf("missing connection: %v", err)
		}
		fds, err := unix.ParseUnixRights(&messages[0])
		if err != nil || len(fds) != 1 {
			t.Fatalf("invalid rights: %v", err)
		}
		file := os.NewFile(uintptr(fds[0]), "target")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		result, err := io.ReadAll(conn)
		_ = conn.Close()
		if err != nil || string(result) != "PINNED" {
			t.Fatalf("wrong target: %q, %v", result, err)
		}
	}
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("broker did not stop on disconnect")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("reconnections not delivered")
	}
}

// The test binary is copied only into the disposable isolation-test jail root.
func TestNativeCapabilities(t *testing.T) {
	if os.Getenv("GOB_CHECK_CLIENT_CAPS") != "1" {
		t.Skip("native client helper")
	}
	caps := [2]unix.CapUserData{}
	if err := unix.Capget(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &caps[0]); err != nil {
		t.Fatal(err)
	}
	for _, c := range caps {
		if c.Effective != 0 || c.Permitted != 0 || c.Inheritable != 0 {
			t.Fatalf("capability set not empty: %+v", caps)
		}
	}
	for c := 0; c < 64; c++ {
		value, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil && err != unix.EINVAL {
			t.Fatal(err)
		}
		if err == nil && value != 0 {
			t.Fatalf("bounding capability %d present", c)
		}
	}
	if _, err := os.Stat("/proc/self"); !os.IsNotExist(err) {
		t.Fatalf("unexpected procfs access: %v", err)
	}
	t.Log("CAPABILITIES_EMPTY")
}

func clientTestArgs(binary string, args []string) []string {
	if binary == "psql" {
		return append([]string{"-v", "ON_ERROR_STOP=1"}, args...)
	}
	return args
}

func routableTestHost(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && ip.IsGlobalUnicast() {
			return ip.String()
		}
	}
	t.Fatal("Docker bridge IPv4 address required by the integration fixture")
	return ""
}
