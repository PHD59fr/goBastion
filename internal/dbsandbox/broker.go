package dbsandbox

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// broker alone owns database credentials and connections to the real server.
// The jail receives only a session-bound stream, never an upstream socket.
type broker struct {
	ctx       context.Context
	host      string
	address   string
	binary    string
	user      string
	password  string
	database  string
	mu        sync.Mutex
	first     net.Conn
	pgCancels map[uint64]func(context.Context) error
	touch     func()
}

func newBroker(ctx context.Context, host, address, binary string, args, env []string, first net.Conn) (*broker, []string, []string) {
	b := &broker{ctx: ctx, host: host, address: address, binary: binary, first: first, pgCancels: make(map[uint64]func(context.Context) error)}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-u", "-U", "--user":
			if i+1 < len(args) {
				b.user = args[i+1]
				i++
			}
		case "-d", "--dbname":
			if i+1 < len(args) {
				b.database = args[i+1]
				i++
			}
		case "-n":
			if binary == "redis-cli" && i+1 < len(args) {
				b.database = args[i+1]
				i++
			}
		case "-h", "-p", "-P", "-v":
			i++
		default:
			if binary == "mariadb" && !strings.HasPrefix(args[i], "-") {
				b.database = args[i]
			}
		}
	}
	var clientEnv []string
	for _, value := range env {
		key, secret, _ := strings.Cut(value, "=")
		switch key {
		case "MYSQL_PWD", "PGPASSWORD", "REDISCLI_AUTH":
			if (binary == "mariadb" && key == "MYSQL_PWD") || (binary == "psql" && key == "PGPASSWORD") || (binary == "redis-cli" && key == "REDISCLI_AUTH") {
				b.password = secret
			}
		case "PGSSLMODE", "PGSSLROOTCERT", "PGGSSENCMODE":
			// Upstream TLS belongs to the broker; these are never inherited.
		default:
			clientEnv = append(clientEnv, value)
		}
	}
	clientArgs := append([]string(nil), args...)
	switch binary {
	case "mariadb":
		// This leg is a private namespace/socketpair, not the database network.
		// TLS with certificate verification is mandatory on the broker's uplink.
		clientArgs = append([]string{"--skip-ssl", "--skip-password"}, clientArgs...)
	case "psql":
		clientEnv = append(clientEnv, "PGSSLMODE=disable", "PGGSSENCMODE=disable", "PGPASSFILE=/dev/null")
	case "redis-cli":
		clientArgs = append([]string{"-e"}, clientArgs...)
	}
	return b, clientArgs, clientEnv
}

func (b *broker) dial(ctx context.Context) (net.Conn, error) {
	b.mu.Lock()
	first := b.first
	b.first = nil
	b.mu.Unlock()
	conn := first
	var err error
	if conn == nil {
		conn, err = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", b.address)
	}
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		context.AfterFunc(b.ctx, func() { _ = conn.Close() })
	}
	return conn, err
}

func (b *broker) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: b.host, MinVersion: tls.VersionTLS12}
}

func (b *broker) serve(control *os.File) {
	defer func() { _ = control.Close() }()
	rawControl, err := control.SyscallConn()
	if err != nil {
		return
	}
	stop := context.AfterFunc(b.ctx, func() { _ = control.Close() })
	defer stop()
	for count := 0; count < 128; {
		var request [1]byte
		if _, err := control.Read(request[:]); err != nil {
			return
		}
		if request[0] == 'A' {
			if b.touch != nil {
				b.touch()
			}
			continue
		}
		if request[0] != 1 {
			return
		}
		count++
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return
		}
		local, peer := os.NewFile(uintptr(pair[0]), "broker-session"), os.NewFile(uintptr(pair[1]), "worker-session")
		conn, err := net.FileConn(local)
		_ = local.Close()
		if err != nil {
			_ = peer.Close()
			return
		}
		if b.touch != nil {
			conn = &activityConn{Conn: conn, touch: b.touch}
		}
		// Hold the descriptor through the syscall, even if cancellation closes
		// control concurrently. RawConn also preserves its nonblocking mode.
		rights := unix.UnixRights(int(peer.Fd()))
		var sendErr error
		err = rawControl.Write(func(fd uintptr) bool {
			for {
				sendErr = unix.Sendmsg(int(fd), []byte{1}, rights, nil, unix.MSG_DONTWAIT)
				if errors.Is(sendErr, unix.EINTR) {
					continue
				}
				return !errors.Is(sendErr, unix.EAGAIN) && !errors.Is(sendErr, unix.EWOULDBLOCK)
			}
		})
		if err == nil {
			err = sendErr
		}
		_ = peer.Close()
		if err != nil {
			_ = conn.Close()
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			stop := context.AfterFunc(b.ctx, func() { _ = conn.Close() })
			defer stop()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			var err error
			switch b.binary {
			case "mariadb":
				err = b.mysql(conn)
			case "psql":
				err = b.postgres(conn)
			case "redis-cli":
				err = b.redis(conn)
			default:
				err = fmt.Errorf("invalid broker protocol")
			}
			if err != nil && b.ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
				if b.binary == "redis-cli" {
					_, _ = io.WriteString(conn, "-ERR Upstream verified TLS or authentication failed\r\n")
				}
				slog.Warn("db_broker_session_failed", "protocol", b.binary, "error", err)
			}
		}()
	}
}

func relayAuthenticated(ctx context.Context, client, upstream net.Conn) error {
	return relayWithUpload(ctx, client, upstream, func(dst io.Writer, src io.Reader) error { _, err := io.Copy(dst, src); return err })
}

func relayWithUpload(ctx context.Context, client, upstream net.Conn, upload func(io.Writer, io.Reader) error) error {
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = upstream.Close() })
	defer stop()
	defer func() { _ = upstream.Close() }()
	done := make(chan error, 1)
	go func() {
		err := upload(upstream, client)
		if err != nil && !errors.Is(err, io.EOF) {
			_ = upstream.Close()
		} else if half, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			_ = upstream.Close()
		}
		done <- err
	}()
	_, err := io.Copy(client, upstream)
	_ = client.Close()
	if inputErr := <-done; inputErr != nil && !errors.Is(inputErr, io.EOF) {
		return inputErr
	}
	return err
}

func argumentPort(address string) uint16 {
	_, value, _ := net.SplitHostPort(address)
	port, _ := strconv.ParseUint(value, 10, 16)
	return uint16(port)
}
