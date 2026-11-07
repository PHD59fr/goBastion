package sftpProxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/sessionlimit"
	"goBastion/internal/utils/sshHostKey"
	"goBastion/internal/utils/validation"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gorm.io/gorm"
)

// stdinoutConn wraps os.Stdin/Stdout as net.Conn for use with ssh.NewServerConn.
// Any bytes written by goBastion before this point (welcome banner, logo) are
// skipped by the SSH client per RFC 4253 §4.2: clients MUST discard lines that
// do not begin with "SSH-" before the version exchange.
type stdinoutConn struct{ watch *sessionlimit.Watch }

func (c *stdinoutConn) Read(p []byte) (n int, err error) {
	n, err = os.Stdin.Read(p)
	if n > 0 && c.watch != nil {
		c.watch.Touch()
	}
	return
}
func (c *stdinoutConn) Write(p []byte) (n int, err error) {
	n, err = os.Stdout.Write(p)
	if n > 0 && c.watch != nil {
		c.watch.Touch()
	}
	return
}
func (c *stdinoutConn) Close() error                       { _ = os.Stdin.Close(); return os.Stdout.Close() }
func (c *stdinoutConn) LocalAddr() net.Addr                { return &net.UnixAddr{Name: "stdin", Net: "unix"} }
func (c *stdinoutConn) RemoteAddr() net.Addr               { return &net.UnixAddr{Name: "stdout", Net: "unix"} }
func (c *stdinoutConn) SetDeadline(_ time.Time) error      { return nil }
func (c *stdinoutConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stdinoutConn) SetWriteDeadline(_ time.Time) error { return nil }

// Proxy connects to the target via SSH using the egress key, requests the sftp
// subsystem, then presents a minimal SSH server on stdin/stdout so the local
// sftp client can communicate without needing its own key on the target.
//
// Client SSH config:
//
//	Host myserver
//	  User root
//	  ProxyCommand ssh -p 2222 -- user@bastion "sftp-session root@[%h]:%p"
func Proxy(db *gorm.DB, access models.AccessRight) error {
	// 1. Connect to the target with the egress key.
	signer, err := ssh.ParsePrivateKey([]byte(access.PrivateKey))
	if err != nil {
		return fmt.Errorf("parse egress key: %w", err)
	}

	targetAddr := net.JoinHostPort(validation.UnbracketHost(access.Server), fmt.Sprintf("%d", access.Port))
	netConn, err := net.DialTimeout("tcp", targetAddr, time.Duration(config.Get().Proxy.SFTPDialTimeout))
	if err != nil {
		return fmt.Errorf("connect to target %s: %w", targetAddr, err)
	}
	defer func() { _ = netConn.Close() }()
	rawConn := netConn
	watch := sessionlimit.Start(func() { _ = rawConn.Close(); _ = os.Stdin.Close(); _ = os.Stdout.Close() })
	defer watch.Stop()
	netConn = &sessionlimit.Conn{Conn: netConn, Watch: watch}
	if timeout := time.Duration(config.Get().Proxy.SFTPSSHTimeout); timeout > 0 {
		_ = netConn.SetDeadline(time.Now().Add(timeout))
	}

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("resolve current user: %w", err)
	}
	knownHostsFile := filepath.Join(config.Get().Paths.HomeBaseDir, utils.NormalizeUsername(currentUser.Username), ".ssh", "known_hosts")
	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return fmt.Errorf("load known_hosts callback: %w", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            access.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         time.Duration(config.Get().Proxy.SFTPSSHTimeout),
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, targetAddr, clientConfig)
	if err != nil {
		return fmt.Errorf("ssh connect to %s: %w", targetAddr, err)
	}
	_ = netConn.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() { _ = client.Close() }()

	// 2. Request the sftp subsystem on the target.
	target, targetRequests, err := client.OpenChannel("session", nil)
	if err != nil {
		return fmt.Errorf("open ssh session: %w", err)
	}
	defer func() { _ = target.Close() }()
	ok, err := target.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil {
		return fmt.Errorf("request sftp subsystem: %w", err)
	}
	if !ok {
		return fmt.Errorf("request sftp subsystem: target rejected request")
	}

	// 3. Load the stable host key used by the fake SSH server presented to the
	// local sftp client. This allows clients to pin the host key in known_hosts.
	hostSigner, _, _, err := sshHostKey.EnsureSFTPProxyHostKey(db, false)
	if err != nil {
		return fmt.Errorf("load SFTP proxy host key: %w", err)
	}

	// 4. Present a minimal SSH server on stdin/stdout.
	// The user is already authenticated to sshd, so we accept any auth method.
	serverConfig := &ssh.ServerConfig{
		NoClientAuth: true,
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	serverConn, newChans, globalReqs, err := serverHandshake(&stdinoutConn{watch: watch}, serverConfig, time.Duration(config.Get().Proxy.SFTPSSHTimeout))
	if err != nil {
		return fmt.Errorf("ssh server handshake: %w", err)
	}
	defer func() { _ = serverConn.Close() }()
	go ssh.DiscardRequests(globalReqs)

	// 5. Accept the session channel and sftp subsystem request from the client.
	for newChan := range newChans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		ch, requests, err := newChan.Accept()
		if err != nil {
			return fmt.Errorf("accept channel: %w", err)
		}

		// Only the SFTP subsystem is supported on this authenticated transport.
		requestsDone := make(chan struct{})
		go func(reqs <-chan *ssh.Request) {
			defer close(requestsDone)
			started := false
			for req := range reqs {
				var payload struct{ Name string }
				accept := !started && req.Type == "subsystem" && ssh.Unmarshal(req.Payload, &payload) == nil && payload.Name == "sftp"
				if accept {
					started = true
				}
				_ = req.Reply(accept, nil)
			}
		}(requests)

		// 6. Pipe raw sftp bytes between the client channel and the target session.
		relaySFTP(ch, target, targetRequests)
		// Wait for the peer's channel-close acknowledgement before tearing down
		// the transport, including when it had already half-closed its input.
		<-requestsDone
		return nil
	}
	return nil
}

func relaySFTP(front, target ssh.Channel, targetRequests <-chan *ssh.Request) {
	closeChannels := func() { _ = target.Close(); _ = front.Close() }
	var pending sync.WaitGroup
	pending.Go(func() {
		if _, err := io.Copy(target, front); err != nil {
			slog.Warn("sftp_proxy_client_to_target", "error", err)
			closeChannels()
			return
		}
		// A client half-close must still allow the target's final reply through.
		_ = target.CloseWrite()
	})
	requestsDone := make(chan struct{})
	go func() {
		defer close(requestsDone)
		for req := range targetRequests {
			if req.Type == "exit-status" || req.Type == "exit-signal" {
				_, _ = front.SendRequest(req.Type, false, req.Payload)
			}
			_ = req.Reply(false, nil)
		}
	}()
	var output sync.WaitGroup
	copyOutput := func(dst io.Writer, src io.Reader) {
		if _, err := io.Copy(dst, src); err != nil {
			slog.Warn("sftp_proxy_target_to_client", "error", err)
			closeChannels()
		}
	}
	output.Go(func() { copyOutput(front, target) })
	output.Go(func() { copyOutput(front.Stderr(), target.Stderr()) })
	output.Wait()
	// Both output streams are drained. Closing the channels also releases an
	// upload blocked on the local client or on the target's receive window.
	_ = target.Close()
	<-requestsDone
	_ = front.Close()
	pending.Wait()
}

func serverHandshake(conn net.Conn, cfg *ssh.ServerConfig, timeout time.Duration) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	if timeout <= 0 {
		return ssh.NewServerConn(conn, cfg)
	}
	timer := time.AfterFunc(timeout, func() { _ = conn.Close() })
	defer timer.Stop()
	return ssh.NewServerConn(conn, cfg)
}
