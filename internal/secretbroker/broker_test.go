package secretbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrokerAllowsRegisteredOperationAndRejectsUnknown(t *testing.T) {
	sock := brokerTestPath(t)
	srv := NewServer(sock)
	srv.Handle("ping", func(_ context.Context, peer Peer, req Request) (json.RawMessage, error) {
		if peer.UID != uint32(os.Getuid()) {
			return nil, fmt.Errorf("unexpected peer uid %d", peer.UID)
		}
		return json.RawMessage(`{"pong":true}`), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("broker socket not created")
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp, err := Call(context.Background(), sock, Request{Operation: "ping"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || string(resp.Data) != `{"pong":true}` {
		t.Fatalf("unexpected response: %+v", resp)
	}
	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0660 {
		t.Fatalf("socket must allow owner/group connections only: %o", info.Mode().Perm())
	}

	resp, err = Call(context.Background(), sock, Request{Operation: "decrypt-anything"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Error != "operation not allowed" {
		t.Fatalf("unregistered operation was allowed: %+v", resp)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not stop")
	}
}

func brokerTestPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "broker.sock")
}

func startBroker(t *testing.T, srv *Server) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("broker did not stop")
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(srv.path); err == nil {
			return cancel
		}
		if time.Now().After(deadline) {
			t.Fatal("broker socket not created")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBrokerDoesNotReplaceExistingPaths(t *testing.T) {
	for _, kind := range []string{"file", "socket", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := brokerTestPath(t)
			switch kind {
			case "file":
				if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "socket":
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = listener.Close() }()
			case "symlink":
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if err := NewServer(path).Serve(ctx); err == nil {
				t.Fatal("existing path replaced")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("existing path changed: %v", err)
			}
		})
	}
}

func TestBrokerRejectsUntrustedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := NewServer(filepath.Join(dir, "broker.sock")).Serve(context.Background()); err == nil {
		t.Fatal("world-writable socket directory accepted")
	}
}

func TestBrokerShutdownPreservesReplacementPath(t *testing.T) {
	path := brokerTestPath(t)
	srv := NewServer(path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	// A round trip ensures the listener finished configuring before the swap.
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := Call(context.Background(), path, Request{Operation: "unknown"}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("broker did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not stop")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "replacement" {
		t.Fatalf("shutdown removed replacement: %v", err)
	}
}

func TestBrokerRejectsUnauthorizedAndOversizedRequests(t *testing.T) {
	for _, kind := range []string{"uid", "size"} {
		t.Run(kind, func(t *testing.T) {
			srv := NewServer(brokerTestPath(t))
			var called atomic.Bool
			srv.Handle("ping", func(context.Context, Peer, Request) (json.RawMessage, error) {
				called.Store(true)
				return nil, nil
			})
			if kind == "uid" {
				srv.AllowUIDs = map[uint32]bool{uint32(os.Getuid()): false}
			}
			startBroker(t, srv)
			conn, err := net.Dial("unix", srv.path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			payload := ""
			if kind == "size" {
				payload = strings.Repeat("x", maxMessageBytes)
			}
			// A rejected UID can close the connection before the write completes.
			_, _ = fmt.Fprintf(conn, `{"operation":"ping","payload":"%s"}`, payload)
			var response Response
			if err := json.NewDecoder(conn).Decode(&response); err != nil {
				t.Fatal(err)
			}
			if response.OK || response.Error == "" || called.Load() {
				t.Fatalf("request reached handler: %+v", response)
			}
		})
	}
}

func TestCallCancellationAfterConnect(t *testing.T) {
	srv := NewServer(brokerTestPath(t))
	entered := make(chan struct{})
	srv.Handle("wait", func(ctx context.Context, _ Peer, _ Request) (json.RawMessage, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	startBroker(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Call(ctx, srv.path, Request{Operation: "wait"})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler not entered")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Call ignored cancellation after dialing")
	}
}

func TestBrokerBoundsConcurrentHandlers(t *testing.T) {
	srv := NewServer(brokerTestPath(t))
	entered := make(chan struct{}, maxConnections+1)
	srv.Handle("wait", func(ctx context.Context, _ Peer, _ Request) (json.RawMessage, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	cancel := startBroker(t, srv)
	for i := 0; i < maxConnections; i++ {
		conn, err := net.Dial("unix", srv.path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := json.NewEncoder(conn).Encode(Request{Operation: "wait"}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("handler not entered")
		}
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err := Call(ctx, srv.path, Request{Operation: "wait"}); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("excess connection was not rejected promptly: %v", err)
	}
	select {
	case <-entered:
		t.Fatal("concurrent handler limit exceeded")
	default:
	}
	cancel()
}
