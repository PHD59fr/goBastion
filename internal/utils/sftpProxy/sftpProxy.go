package sftpProxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/sshHostKey"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gorm.io/gorm"
)

// stdinoutConn wraps os.Stdin/Stdout as net.Conn for use with ssh.NewServerConn.
// Any bytes written by goBastion before this point (welcome banner, logo) are
// skipped by the SSH client per RFC 4253 §4.2: clients MUST discard lines that
// do not begin with "SSH-" before the version exchange.
type stdinoutConn struct{}

func (c *stdinoutConn) Read(p []byte) (n int, err error)   { return os.Stdin.Read(p) }
func (c *stdinoutConn) Write(p []byte) (n int, err error)  { return os.Stdout.Write(p) }
func (c *stdinoutConn) Close() error                       { return nil }
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
//	  ProxyCommand ssh -p 2222 -- user@bastion "sftp-session root@%h:%p"
func Proxy(db *gorm.DB, access models.AccessRight) error {
	// 1. Connect to the target with the egress key.
	signer, err := ssh.ParsePrivateKey([]byte(access.PrivateKey))
	if err != nil {
		return fmt.Errorf("parse egress key: %w", err)
	}

	targetAddr := net.JoinHostPort(access.Server, fmt.Sprintf("%d", access.Port))
	netConn, err := net.DialTimeout("tcp", targetAddr, time.Duration(config.Get().Proxy.SFTPDialTimeout))
	if err != nil {
		return fmt.Errorf("connect to target %s: %w", targetAddr, err)
	}
	defer func() { _ = netConn.Close() }()

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("resolve current user: %w", err)
	}
	knownHostsFile := filepath.Join(config.Get().Paths.HomeBaseDir, utils.NormalizeUsername(currentUser.Username), ".ssh", "known_hosts")
	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return fmt.Errorf("load known_hosts callback: %w", err)
	}

	sshServerAddr := targetAddr
	if access.Port == config.Get().SSH.DefaultPort {
		sshServerAddr = access.Server
	}

	clientConfig := &ssh.ClientConfig{
		User:            access.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         time.Duration(config.Get().Proxy.SFTPSSHTimeout),
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, sshServerAddr, clientConfig)
	if err != nil {
		return fmt.Errorf("ssh connect to %s: %w", targetAddr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() { _ = client.Close() }()

	// 2. Request the sftp subsystem on the target.
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	if err = session.RequestSubsystem("sftp"); err != nil {
		return fmt.Errorf("request sftp subsystem: %w", err)
	}

	targetIn, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("target stdin pipe: %w", err)
	}
	targetOut, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("target stdout pipe: %w", err)
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

	serverConn, newChans, globalReqs, err := ssh.NewServerConn(&stdinoutConn{}, serverConfig)
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

		// Acknowledge subsystem and other requests silently.
		go func(reqs <-chan *ssh.Request) {
			for req := range reqs {
				_ = req.Reply(req.Type == "subsystem", nil)
			}
		}(requests)

		// 6. Pipe raw sftp bytes between the client channel and the target session.
		done := make(chan struct{}, 2)
		go func() {
			defer func() { done <- struct{}{} }()
			if _, err := io.Copy(targetIn, ch); err != nil {
				slog.Warn("sftp_proxy_client_to_target", slog.String("error", err.Error()))
			}
			_ = targetIn.Close()
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			if _, err := io.Copy(ch, targetOut); err != nil {
				slog.Warn("sftp_proxy_target_to_client", slog.String("error", err.Error()))
			}
			_ = ch.CloseWrite()
		}()
		<-done
		<-done
		return nil
	}
	return nil
}
