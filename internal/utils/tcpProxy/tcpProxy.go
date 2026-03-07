package tcpProxy

import (
	"fmt"
	"io"
	"net"
	"os"
)

// Proxy opens a raw TCP connection to host:port and pipes stdin/stdout through it.
// Used for transparent SCP/SFTP/rsync passthrough via SSH ProxyCommand or ProxyJump.
// Example client config:
//
//	Host target
//	  ProxyCommand ssh -p 2222 %r@bastion -W %h:%p
func Proxy(host, port string) error {
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("cannot connect to %s:%s: %w", host, port, err)
	}
	tc := conn.(*net.TCPConn)
	defer func() { _ = tc.Close() }()

	done := make(chan struct{}, 2)

	// stdin → remote: when stdin closes (SCP/rsync finished sending), signal remote EOF.
	go func() {
		_, _ = io.Copy(tc, os.Stdin)
		_ = tc.CloseWrite() // half-close: remote sees EOF, can still send back
		done <- struct{}{}
	}()

	// remote → stdout: when remote closes, we're done.
	go func() {
		_, _ = io.Copy(os.Stdout, tc)
		done <- struct{}{}
	}()

	// Wait for the first direction to finish, then give the other a moment.
	// Closing the connection unblocks the other goroutine immediately.
	<-done
	_ = tc.Close()
	<-done
	return nil
}
