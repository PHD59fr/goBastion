package dbsandbox

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTerminalActivityDoesNotConsumeConnectionAllowance(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(pair[0], true); err != nil {
		_ = unix.Close(pair[0])
		_ = unix.Close(pair[1])
		t.Fatal(err)
	}
	server, client := os.NewFile(uintptr(pair[0]), "broker"), os.NewFile(uintptr(pair[1]), "worker")
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var touches atomic.Int64
	b, _, _ := newBroker(ctx, "fixture", "127.0.0.1:1", "psql", nil, nil, nil)
	b.touch = func() { touches.Add(1) }
	done := make(chan struct{})
	go func() { b.serve(server); close(done) }()
	defer func() { cancel(); <-done }()
	for range 200 {
		if _, err := client.Write([]byte{'A'}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	data, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	_, n, _, _, err := unix.Recvmsg(int(client.Fd()), data, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:n])
	if err != nil || len(msgs) != 1 {
		t.Fatalf("connection was not delivered after 200 activity events: %v", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		t.Fatalf("invalid connection descriptor: %v", err)
	}
	_ = unix.Close(fds[0])
	if touches.Load() != 200 {
		t.Fatalf("activity was not delivered: %d", touches.Load())
	}
}
