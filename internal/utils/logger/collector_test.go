package logger

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCheckedUnixIDRejectsWraparound(t *testing.T) {
	if id, err := checkedUnixID(0); err != nil || id != 0 {
		t.Fatalf("root UID: %d, %v", id, err)
	}
	invalid := []int{-1}
	if strconv.IntSize == 64 {
		maximum := uint64(1)<<32 - 1
		if id, err := checkedUnixID(int(maximum)); err != nil || uint64(id) != maximum {
			t.Fatalf("maximum UID: %d, %v", id, err)
		}
		invalid = append(invalid, int(maximum+1), int(maximum+2))
	}
	for _, uid := range invalid {
		if id, err := checkedUnixID(uid); err == nil || id != 0 {
			t.Fatalf("UID %d accepted: %d, %v", uid, id, err)
		}
	}
}

type testAuditSink struct {
	bytes.Buffer
	syncErr  error
	writeErr error
}

func (s *testAuditSink) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.Buffer.Write(p)
}

func (s *testAuditSink) Sync() error { return s.syncErr }

func startTestCollector(t *testing.T, sink auditSink) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveAudit(ctx, listener, sink) }()
	t.Cleanup(func() { cancel(); _ = listener.Close() })
	return path, cancel, done
}

func TestCollectorPersistsKernelSenderMetadata(t *testing.T) {
	sink := &testAuditSink{}
	path, cancel, done := startTestCollector(t, sink)
	payload := []byte(`{"msg":"session_event","_user":"claimed","_collector_uid":999,"_collector_pid":-1,"_collector_event_id":"forged","_collector_received_at":"forged"}`)
	if n, err := writeAuditRecord(path, payload, uint32(os.Geteuid())); err != nil || n != len(payload) {
		t.Fatalf("write: %d, %v", n, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	record := decodeJSON(t, sink.String())
	if record["_collector_uid"] != float64(os.Geteuid()) || record["_collector_pid"] != float64(os.Getpid()) {
		t.Fatalf("sender metadata not from kernel: %v", record)
	}
	if record["_collector_event_id"] == "forged" || record["_collector_received_at"] == "forged" {
		t.Fatal("collector metadata was forged")
	}
	if record["_user"] != "claimed" {
		t.Fatal("business claim unexpectedly changed")
	}
}

func TestCollectorConcurrentRecordsRemainWhole(t *testing.T) {
	sink := &testAuditSink{}
	path, cancel, done := startTestCollector(t, sink)
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			payload, _ := json.Marshal(map[string]any{"index": i})
			if _, err := writeAuditRecord(path, payload, uint32(os.Geteuid())); err != nil {
				t.Errorf("write: %v", err)
			}
		}()
	}
	workers.Wait()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(sink.Bytes()), []byte{'\n'})
	if len(lines) != 16 {
		t.Fatalf("got %d records", len(lines))
	}
	ids := map[any]bool{}
	for _, line := range lines {
		record := decodeJSON(t, string(line))
		if ids[record["_collector_event_id"]] {
			t.Fatal("duplicate collector ID")
		}
		ids[record["_collector_event_id"]] = true
	}
}

func TestCollectorDoesNotAcknowledgeStorageFailure(t *testing.T) {
	for _, failure := range []struct {
		name              string
		writeErr, syncErr error
	}{
		{"disk_full", syscall.ENOSPC, nil}, {"sync_failed", nil, syscall.EIO},
	} {
		t.Run(failure.name, func(t *testing.T) {
			sink := &testAuditSink{writeErr: failure.writeErr, syncErr: failure.syncErr}
			path, _, done := startTestCollector(t, sink)
			if _, err := writeAuditRecord(path, []byte(`{"msg":"event"}`), uint32(os.Geteuid())); err == nil {
				t.Fatal("storage failure acknowledged")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("collector storage failure hidden")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("collector did not stop")
			}
		})
	}
}

type gatedAuditSink struct {
	bytes.Buffer
	syncStarted chan struct{}
	releaseSync chan struct{}
}

func (s *gatedAuditSink) Sync() error {
	close(s.syncStarted)
	<-s.releaseSync
	return nil
}

func TestCollectorAcknowledgesOnlyAfterSync(t *testing.T) {
	sink := &gatedAuditSink{syncStarted: make(chan struct{}), releaseSync: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(sink.releaseSync) }) }
	defer unblock()
	path, cancel, done := startTestCollector(t, sink)
	written := make(chan error, 1)
	go func() {
		_, err := writeAuditRecord(path, []byte(`{"msg":"login"}`), uint32(os.Geteuid()))
		written <- err
	}()
	select {
	case <-sink.syncStarted:
	case <-time.After(time.Second):
		t.Fatal("collector did not start sync")
	}
	select {
	case err := <-written:
		t.Fatalf("client completed before durable sync: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	unblock()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCollectorRejectsOversizedFrameAndKeepsServing(t *testing.T) {
	sink := &testAuditSink{}
	path, cancel, done := startTestCollector(t, sink)
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], maxAuditRecord+1)
	if _, err := conn.Write(frame[:]); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var ack [1]byte
	if n, err := conn.Read(ack[:]); n != 0 || err == nil {
		t.Fatal("oversized frame acknowledged")
	}
	_ = conn.Close()
	if _, err := writeAuditRecord(path, []byte(`{"msg":"valid"}`), uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if bytes.Count(sink.Bytes(), []byte{'\n'}) != 1 {
		t.Fatal("invalid frame was stored")
	}
}

func TestAuditClientRejectsWrongCollectorUID(t *testing.T) {
	sink := &testAuditSink{}
	path, cancel, done := startTestCollector(t, sink)
	if _, err := writeAuditRecord(path, []byte(`{}`), uint32(os.Geteuid()+1)); err == nil {
		t.Fatal("wrong server UID accepted")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if sink.Len() != 0 {
		t.Fatal("record sent to untrusted collector")
	}
}

type shortAuditSink struct{}

func (shortAuditSink) Write(p []byte) (int, error) { return len(p) / 2, nil }
func (shortAuditSink) Sync() error                 { return nil }

func TestCollectorReportsShortWrite(t *testing.T) {
	c := auditCollector{sink: shortAuditSink{}}
	if err := c.persist([]byte(`{}`), &unix.Ucred{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
}

func TestAuditClientMissingCollector(t *testing.T) {
	if _, err := (auditSocketWriter{path: filepath.Join(t.TempDir(), "missing")}).Write([]byte(`{}`)); err == nil {
		t.Fatal("missing collector accepted")
	}
}

func TestCollectorRecoversStaleSocketAndKeepsLockInode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.sock")
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	listener, release, err := listenAudit(dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	lockPath := filepath.Join(dir, "collector.lock")
	before, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	// A concurrent collector must leave both the socket and lock untouched.
	if other, unlock, err := listenAudit(dir, uint32(os.Geteuid())); err == nil {
		unlock()
		_ = other.Close()
		t.Fatal("concurrent collector accepted")
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("live listener lost: %v", err)
	}
	_ = conn.Close()
	_ = listener.Close()
	release()
	after, err := os.Stat(lockPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lifecycle lock inode removed")
	}
	_, releaseAgain, err := listenAudit(dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	releaseAgain()
}

func TestCollectorPreservesExistingLiveSocket(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.sock")
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = old.Close() }()
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, release, err := listenAudit(dir, uint32(os.Geteuid())); err == nil {
		release()
		t.Fatal("live legacy listener replaced")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("live socket changed")
	}
}

func TestCollectorRejectsUnsafeRuntimeEntries(t *testing.T) {
	for _, name := range []string{"socket_symlink", "socket_regular", "lock_symlink", "lock_hardlink", "writable_directory"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch name {
			case "socket_symlink":
				err = os.Symlink(target, filepath.Join(dir, "audit.sock"))
			case "socket_regular":
				err = os.WriteFile(filepath.Join(dir, "audit.sock"), []byte("preserve"), 0600)
			case "lock_symlink":
				err = os.Symlink(target, filepath.Join(dir, "collector.lock"))
			case "lock_hardlink":
				err = os.Link(target, filepath.Join(dir, "collector.lock"))
			case "writable_directory":
				err = os.Chmod(dir, 0777)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, release, err := listenAudit(dir, uint32(os.Geteuid())); err == nil {
				release()
				t.Fatal("unsafe runtime entry accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "preserve" {
				t.Fatal("target modified")
			}
		})
	}
}
