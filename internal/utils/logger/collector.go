package logger

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"goBastion/internal/config"
	"golang.org/x/sys/unix"
)

const (
	AuditSocketDirectory = "/run/gobastion-audit"
	AuditSocketPath      = AuditSocketDirectory + "/audit.sock"
	maxAuditRecord       = 64 * 1024
	auditTimeout         = 2 * time.Second
)

// auditSocketWriter requires an acknowledgment after the collector has synced
// the record. An error never falls back to the writable session filesystem.
type auditSocketWriter struct{ path string }

func (w auditSocketWriter) Write(p []byte) (int, error) {
	return writeAuditRecord(w.path, p, 0)
}

func writeAuditRecord(path string, p []byte, expectedUID uint32) (int, error) {
	if len(p) == 0 || len(p) > maxAuditRecord {
		return 0, errors.New("audit record exceeds size limit")
	}
	conn, err := net.DialTimeout("unix", path, auditTimeout)
	if err != nil {
		return 0, errors.New("audit collector unavailable")
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(auditTimeout)); err != nil {
		return 0, errors.New("audit collector deadline unavailable")
	}
	peer, err := auditPeer(conn.(*net.UnixConn))
	if err != nil || peer.Uid != expectedUID {
		return 0, errors.New("audit collector is not root")
	}
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], uint32(len(p)))
	if n, err := conn.Write(frame[:]); err != nil || n != len(frame) {
		return 0, errors.New("audit collector write failed")
	}
	if n, err := conn.Write(p); err != nil || n != len(p) {
		return 0, errors.New("audit collector write failed")
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
		return 0, errors.New("audit collector did not acknowledge durable storage")
	}
	return len(p), nil
}

func auditPeer(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		peer, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return peer, socketErr
}

type auditSink interface {
	io.Writer
	Sync() error
}

type auditCollector struct {
	mu   sync.Mutex
	sink auditSink
}

func (c *auditCollector) persist(data []byte, peer *unix.Ucred) error {
	var record map[string]json.RawMessage
	if err := json.Unmarshal(data, &record); err != nil || record == nil {
		return errors.New("invalid audit JSON object")
	}
	// These fields cannot be supplied or overwritten by the session. In
	// particular, _user and event timestamps remain untrusted payload fields.
	fields := map[string]any{
		"_collector_uid": peer.Uid, "_collector_gid": peer.Gid,
		"_collector_pid": peer.Pid, "_collector_event_id": uuid.NewString(),
		"_collector_received_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	for key, value := range fields {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		record[key] = encoded
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.sink.Write(encoded)
	if err != nil {
		return err
	}
	if n != len(encoded) {
		return io.ErrShortWrite
	}
	return c.sink.Sync()
}

func (c *auditCollector) receive(conn *net.UnixConn) error {
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(auditTimeout)); err != nil {
		return nil
	}
	peer, err := auditPeer(conn)
	if err != nil {
		return nil
	}
	var frame [4]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		return nil
	}
	size := binary.BigEndian.Uint32(frame[:])
	if size == 0 || size > maxAuditRecord {
		return nil
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil || !json.Valid(data) {
		return nil
	}
	// Invalid JSON objects are a client error; storage errors are fatal to
	// the collector so PID 1 stops accepting new sessions.
	var record map[string]json.RawMessage
	if err := json.Unmarshal(data, &record); err != nil || record == nil {
		return nil
	}
	if err := c.persist(data, peer); err != nil {
		return err
	}
	_, _ = conn.Write([]byte{1})
	return nil
}

func serveAudit(ctx context.Context, listener *net.UnixListener, sink auditSink) error {
	c := auditCollector{sink: sink}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, 1)
	slots := make(chan struct{}, 32)
	var workers sync.WaitGroup
	defer workers.Wait()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			select {
			case failure := <-failures:
				return failure
			default:
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				if err := c.receive(conn); err != nil {
					select {
					case failures <- err:
					default:
					}
					cancel()
				}
			}()
		default:
			_ = conn.Close()
		}
	}
}

func checkedUnixID(v int) (uint32, error) {
	if v < 0 || uint64(v) > uint64(^uint32(0)) {
		return 0, errors.New("invalid unix id")
	}
	return uint32(v), nil
}

// RunAuditCollector serves the fixed production socket and root-only log file.
// The lifecycle lock permits recovery of a socket left by an abrupt shutdown.
func RunAuditCollector(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("audit collector requires root")
	}
	group, err := user.LookupGroup("gobastion")
	if err != nil {
		return errors.New("audit group unavailable")
	}
	groupID, err := strconv.Atoi(group.Gid)
	if err != nil {
		return errors.New("invalid audit group")
	}
	if err := os.Mkdir(AuditSocketDirectory, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(AuditSocketDirectory)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe audit socket directory")
	}
	if err := os.Chown(AuditSocketDirectory, 0, groupID); err != nil {
		return err
	}
	if err := os.Chmod(AuditSocketDirectory, 0710); err != nil {
		return err
	}
	file, err := openLogFile(config.DefaultLogFilePath())
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	owner, err := checkedUnixID(os.Geteuid())
	if err != nil {
		return err
	}
	listener, release, err := listenAudit(AuditSocketDirectory, owner)
	if err != nil {
		return err
	}
	defer release()
	if err := os.Chown(AuditSocketPath, 0, groupID); err != nil {
		return err
	}
	if err := os.Chmod(AuditSocketPath, 0620); err != nil {
		return err
	}
	if err := serveAudit(ctx, listener, file); err != nil {
		return fmt.Errorf("audit collector stopped: %w", err)
	}
	return nil
}
