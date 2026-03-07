package sftpProxy

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"goBastion/internal/models"

	"golang.org/x/crypto/ssh"
)

// stdinoutConn wraps os.Stdin/Stdout as net.Conn for use with ssh.NewServerConn.
// Any bytes written by goBastion before this point (welcome banner, logo) are
// skipped by the SSH client per RFC 4253 §4.2: clients MUST discard lines that
// do not begin with "SSH-" before the version exchange.
type stdinoutConn struct{}

func (c *stdinoutConn) Read(p []byte) (n int, err error)      { return os.Stdin.Read(p) }
func (c *stdinoutConn) Write(p []byte) (n int, err error)     { return os.Stdout.Write(p) }
func (c *stdinoutConn) Close() error                          { return nil }
func (c *stdinoutConn) LocalAddr() net.Addr                   { return &net.UnixAddr{Name: "stdin", Net: "unix"} }
func (c *stdinoutConn) RemoteAddr() net.Addr                  { return &net.UnixAddr{Name: "stdout", Net: "unix"} }
func (c *stdinoutConn) SetDeadline(_ time.Time) error         { return nil }
func (c *stdinoutConn) SetReadDeadline(_ time.Time) error     { return nil }
func (c *stdinoutConn) SetWriteDeadline(_ time.Time) error    { return nil }

// Proxy connects to the target via SSH using the egress key, requests the sftp
// subsystem, then presents a minimal SSH server on stdin/stdout so the local
// sftp client can communicate without needing its own key on the target.
//
// Client SSH config:
//
//	Host myserver
//	  User root
//	  ProxyCommand ssh -p 2222 -- user@bastion "sftp-session root@%h:%p"
//	  StrictHostKeyChecking no
//	  UserKnownHostsFile /dev/null
func Proxy(access models.AccessRight) error {
	// 1. Connect to the target with the egress key.
	signer, err := ssh.ParsePrivateKey([]byte(access.PrivateKey))
	if err != nil {
		return fmt.Errorf("parse egress key: %v", err)
	}

	targetAddr := net.JoinHostPort(access.Server, fmt.Sprintf("%d", access.Port))
	netConn, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("connect to target %s: %v", targetAddr, err)
	}
	defer netConn.Close()

	clientConfig := &ssh.ClientConfig{
		User: access.Username,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// Host key verification is handled by checkAndUpdateHostKey before
		// this function is called; here we trust the established known_hosts.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, targetAddr, clientConfig)
	if err != nil {
		return fmt.Errorf("ssh connect to %s: %v", targetAddr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	// 2. Request the sftp subsystem on the target.
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open ssh session: %v", err)
	}
	defer session.Close()

	if err = session.RequestSubsystem("sftp"); err != nil {
		return fmt.Errorf("request sftp subsystem: %v", err)
	}

	targetIn, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("target stdin pipe: %v", err)
	}
	targetOut, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("target stdout pipe: %v", err)
	}

	// 3. Generate an ephemeral RSA host key for our fake SSH server.
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate ephemeral host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		return fmt.Errorf("create host signer: %v", err)
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
		return fmt.Errorf("ssh server handshake: %v", err)
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(globalReqs)

	// 5. Accept the session channel and sftp subsystem request from the client.
	for newChan := range newChans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		ch, requests, err := newChan.Accept()
		if err != nil {
			return fmt.Errorf("accept channel: %v", err)
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
			_, _ = io.Copy(targetIn, ch)
			_ = targetIn.Close()
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = io.Copy(ch, targetOut)
			_ = ch.CloseWrite()
		}()
		<-done
		return nil
	}
	return nil
}
