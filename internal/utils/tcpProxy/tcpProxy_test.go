package tcpProxy

import (
	"bytes"
	"goBastion/internal/config"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProxyDrainsResponseAfterClientEOF(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan error, 1)
	response := strings.Repeat("response", 128*1024)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := io.ReadAll(conn)
		if err == nil && string(request) != "request" {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = io.WriteString(conn, response)
		}
		serverDone <- err
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var output bytes.Buffer
	if err := proxyStream(conn.(*net.TCPConn), io.NopCloser(strings.NewReader("request")), &output); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if output.String() != response {
		t.Fatalf("response truncated: %d / %d bytes", output.Len(), len(response))
	}
}

func TestProxyReturnsWhenRemoteClosesBeforeClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	input, writer := io.Pipe()
	defer func() { _ = writer.Close() }()
	done := make(chan error, 1)
	go func() { done <- proxyStream(conn.(*net.TCPConn), input, io.Discard) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy blocked on client input after remote EOF")
	}
}

func TestProxySessionLimits(t *testing.T) {
	for _, name := range []string{"idle", "absolute"} {
		t.Run(name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			if name == "idle" {
				cfg.Session.IdleTimeout = config.Duration(100 * time.Millisecond)
			} else {
				cfg.Session.MaxSessionDuration = config.Duration(100 * time.Millisecond)
			}
			_ = config.Load()
			config.SetForTesting(cfg)
			defer config.ResetForTesting()
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = l.Close() }()
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, err := l.Accept()
				if err == nil {
					defer func() { _ = c.Close() }()
					_, _ = io.Copy(c, c)
				}
			}()
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			input, writer := io.Pipe()
			defer func() { _ = writer.Close() }()
			if name == "absolute" {
				go func() {
					for {
						if _, e := writer.Write([]byte("active")); e != nil {
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
				}()
			}
			done := make(chan error, 1)
			go func() { done <- proxyStream(c.(*net.TCPConn), input, io.Discard) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("session limit did not close proxy")
			}
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Fatal("target connection leaked")
			}
		})
	}
}

func TestProxyTimeoutClosesBlockedOutput(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Session.MaxSessionDuration = config.Duration(100 * time.Millisecond)
	_ = config.Load()
	config.SetForTesting(cfg)
	defer config.ResetForTesting()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer func() { _ = c.Close() }()
			_, _ = c.Write([]byte("blocked response"))
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	outputReader, outputWriter := io.Pipe()
	defer func() { _ = outputReader.Close() }()
	input, inputWriter := io.Pipe()
	defer func() { _ = inputWriter.Close() }()
	done := make(chan error, 1)
	go func() { done <- proxyStream(c.(*net.TCPConn), input, outputWriter) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked client output survived deadline")
	}
}
