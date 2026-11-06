package dbsandbox

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

func (b *broker) postgres(native net.Conn) error {
	var startup pgproto3.StartupMessage
	for {
		var size [4]byte
		if _, err := io.ReadFull(native, size[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(size[:])
		if n < 8 || n > 10000 {
			return fmt.Errorf("invalid PostgreSQL startup length")
		}
		data := make([]byte, n-4)
		if _, err := io.ReadFull(native, data); err != nil {
			return err
		}
		switch binary.BigEndian.Uint32(data[:4]) {
		case 80877103, 80877104: // SSL/GSS: this leg stays inside private FDs.
			if _, err := native.Write([]byte{'N'}); err != nil {
				return err
			}
			continue
		case 80877102:
			if len(data) != 12 {
				return fmt.Errorf("invalid PostgreSQL cancel request")
			}
			key := binary.BigEndian.Uint64(data[4:])
			b.mu.Lock()
			cancel := b.pgCancels[key]
			b.mu.Unlock()
			if cancel == nil {
				return fmt.Errorf("unknown session cancellation key")
			}
			ctx, stop := context.WithTimeout(b.ctx, 5*time.Second)
			defer stop()
			return cancel(ctx)
		case 196608:
			if err := startup.Decode(data); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported PostgreSQL startup protocol")
		}
		break
	}
	if startup.Parameters["user"] != b.user {
		_ = postgresError(native, "This stream is bound to the selected bastion account")
		return fmt.Errorf("invalid client identity in PostgreSQL broker handshake")
	}
	ctx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
	defer cancel()
	cfg, err := pgconn.ParseConfig("sslmode=verify-full")
	if err != nil {
		return err
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Password = b.host, argumentPort(b.address), b.user, b.password
	cfg.Database = startup.Parameters["database"]
	if cfg.Database == "" {
		cfg.Database = b.database
	}
	if cfg.Database == "" {
		cfg.Database = b.user
	}
	cfg.TLSConfig, cfg.Fallbacks = b.tlsConfig(), nil
	cfg.LookupFunc = func(context.Context, string) ([]string, error) {
		host, _, _ := net.SplitHostPort(b.address)
		return []string{host}, nil
	}
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) { return b.dial(ctx) }
	cfg.RuntimeParams = make(map[string]string)
	for key, value := range startup.Parameters {
		if key != "user" && key != "database" {
			cfg.RuntimeParams[key] = value
		}
	}
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		_ = postgresError(native, "Upstream TLS verification or authentication failed; check the bastion log")
		return err
	}
	if err := conn.SyncConn(ctx); err != nil {
		_ = conn.Close(ctx)
		return err
	}
	hijacked, err := conn.Hijack()
	if err != nil {
		_ = conn.Close(ctx)
		return err
	}
	defer func() { _ = hijacked.Conn.Close() }()
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	key := binary.BigEndian.Uint64(token[:])
	b.mu.Lock()
	b.pgCancels[key] = func(ctx context.Context) error { return b.postgresCancel(ctx, hijacked.PID, hijacked.SecretKey) }
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.pgCancels, key); b.mu.Unlock() }()
	var data []byte
	data, err = (&pgproto3.AuthenticationOk{}).Encode(data)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(hijacked.ParameterStatuses))
	for name := range hijacked.ParameterStatuses {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		data, err = (&pgproto3.ParameterStatus{Name: name, Value: hijacked.ParameterStatuses[name]}).Encode(data)
		if err != nil {
			return err
		}
	}
	data, err = (&pgproto3.BackendKeyData{ProcessID: binary.BigEndian.Uint32(token[:4]), SecretKey: token[4:]}).Encode(data)
	if err != nil {
		return err
	}
	data, err = (&pgproto3.ReadyForQuery{TxStatus: hijacked.TxStatus}).Encode(data)
	if err != nil {
		return err
	}
	if _, err := native.Write(data); err != nil {
		return err
	}
	return relayAuthenticated(b.ctx, native, hijacked.Conn)
}

func (b *broker) postgresCancel(ctx context.Context, pid uint32, secret []byte) error {
	remote, err := b.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = remote.Close() }()
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	request := binary.BigEndian.AppendUint32(nil, 8)
	request = binary.BigEndian.AppendUint32(request, 80877103)
	if _, err := remote.Write(request); err != nil {
		return err
	}
	var response [1]byte
	if _, err := io.ReadFull(remote, response[:]); err != nil {
		return err
	}
	if response[0] != 'S' {
		return fmt.Errorf("PostgreSQL cancellation requires upstream TLS")
	}
	secure := tls.Client(remote, b.tlsConfig())
	if err := secure.HandshakeContext(ctx); err != nil {
		return err
	}
	request = binary.BigEndian.AppendUint32(nil, uint32(12+len(secret)))
	request = binary.BigEndian.AppendUint32(request, 80877102)
	request = binary.BigEndian.AppendUint32(request, pid)
	request = append(request, secret...)
	if _, err := secure.Write(request); err != nil {
		return err
	}
	_, err = secure.Read(response[:])
	if err == io.EOF {
		return nil
	}
	return err
}

func postgresError(conn net.Conn, message string) error {
	data, err := (&pgproto3.ErrorResponse{Severity: "FATAL", Code: "08006", Message: message}).Encode(nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}
