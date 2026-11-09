// Package secretbroker provides a minimal root-owned Unix-domain-socket broker
// for scoped secret operations (G1). It authenticates callers with SO_PEERCRED
// and rejects requests that are not explicitly allowlisted. It is not a generic
// decrypt, sign, or connect API.
//
// This package is an incremental G1 slice: infrastructure and policy checks are
// implemented and tested, but full session migration off process-env secrets is
// not yet complete.
package secretbroker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxMessageBytes = 64 * 1024
	maxConnections  = 32
	requestTimeout  = 10 * time.Second
)

// Request is a scoped broker operation. Callers must not be able to request
// arbitrary secret material, arbitrary decryption, or arbitrary network access.
type Request struct {
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Response is returned to an authenticated, authorized caller.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Peer identifies the authenticated Unix socket caller.
type Peer struct {
	UID uint32
	GID uint32
	PID int32
}

// Handler processes one authorized request.
type Handler func(ctx context.Context, peer Peer, req Request) (json.RawMessage, error)

// Server is a root-owned scoped broker.
type Server struct {
	path     string
	handlers map[string]Handler
	// AllowUIDs, when non-empty, restricts callers to these UIDs in addition to
	// any per-handler checks. Configure it before Serve; do not mutate it while
	// serving. The listening socket is also permission-restricted.
	AllowUIDs map[uint32]bool
}

// NewServer creates a broker server. Callers register handlers before Serve.
func NewServer(path string) *Server {
	return &Server{path: path, handlers: map[string]Handler{}}
}

// Handle registers an allowlisted operation.
func (s *Server) Handle(operation string, h Handler) {
	if operation == "" || h == nil {
		return
	}
	s.handlers[operation] = h
}

// Serve accepts connections until ctx is done.
func (s *Server) Serve(ctx context.Context) error {
	if s.path == "" || !filepath.IsAbs(s.path) {
		return errors.New("missing broker socket path")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The caller provisions the directory. Never follow a directory symlink or
	// replace a pre-existing path, including another server's live socket.
	if err := validateSocketDirectory(filepath.Dir(s.path)); err != nil {
		return err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.path, Net: "unix"})
	if err != nil {
		return err
	}
	l.SetUnlinkOnClose(false)
	socket, err := os.Lstat(s.path)
	if err != nil {
		_ = l.Close()
		return err
	}
	defer func() {
		_ = l.Close()
		if current, err := os.Lstat(s.path); err == nil && os.SameFile(socket, current) {
			_ = os.Remove(s.path)
		}
	}()
	if err := os.Chmod(s.path, 0660); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	connections := make(chan struct{}, maxConnections)
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case connections <- struct{}{}:
			go func() {
				defer func() { <-connections }()
				s.serveConn(ctx, conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func validateSocketDirectory(path string) error {
	owner := int64(os.Geteuid())
	if owner < 0 {
		return errors.New("broker effective UID is unavailable")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || !ok || (int64(stat.Uid) != owner && stat.Uid != 0) {
			return errors.New("untrusted broker socket directory")
		}
		if current == path {
			if int64(stat.Uid) != owner || info.Mode().Perm()&0022 != 0 {
				return errors.New("broker directory must be owned by the server and not writable by others")
			}
		} else if info.Mode().Perm()&0022 != 0 && (stat.Uid != 0 || info.Mode()&os.ModeSticky == 0) {
			return errors.New("writable broker directory ancestor")
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	peer, err := peerCred(uc)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: "unauthorized"})
		return
	}
	if len(s.AllowUIDs) > 0 && !s.AllowUIDs[peer.UID] {
		_ = json.NewEncoder(conn).Encode(Response{Error: "unauthorized"})
		return
	}
	var req Request
	decoder := json.NewDecoder(io.LimitReader(conn, maxMessageBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.InputOffset() > maxMessageBytes {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid request"})
		return
	}
	h, ok := s.handlers[req.Operation]
	if !ok {
		_ = json.NewEncoder(conn).Encode(Response{Error: "operation not allowed"})
		return
	}
	data, err := h(ctx, peer, req)
	if err != nil || ctx.Err() != nil || len(data) > maxMessageBytes/2 {
		_ = json.NewEncoder(conn).Encode(Response{Error: "request denied"})
		return
	}
	_ = json.NewEncoder(conn).Encode(Response{OK: true, Data: data})
}

func peerCred(conn *net.UnixConn) (Peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if controlErr != nil {
		return Peer{}, controlErr
	}
	if cred == nil {
		return Peer{}, syscall.EINVAL
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

// Call sends a scoped request to the broker.
func Call(ctx context.Context, path string, req Request) (Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if len(data)+1 > maxMessageBytes {
		return Response{}, errors.New("broker request too large")
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, err
	}
	var resp Response
	decoder := json.NewDecoder(io.LimitReader(conn, maxMessageBytes+1))
	if err := decoder.Decode(&resp); err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, err
	}
	if decoder.InputOffset() > maxMessageBytes {
		return Response{}, errors.New("broker response too large")
	}
	return resp, nil
}
