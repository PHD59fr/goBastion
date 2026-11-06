package tcpProxy

import (
	"fmt"
	"goBastion/internal/config"
	"io"
	"net"
	"os"
	"time"

	"goBastion/internal/utils/sessionlimit"
	"goBastion/internal/utils/validation"
)

// Proxy opens a raw TCP connection to host:port and pipes stdin/stdout through it.
// Used for transparent SCP/SFTP/rsync passthrough via SSH ProxyCommand or ProxyJump.
// Example client config:
//
//	Host target
//	  ProxyCommand ssh -p 2222 -- %r@bastion "-W [%h]:%p"
func Proxy(host, port string) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(validation.UnbracketHost(host), port), time.Duration(config.Get().Proxy.TCPConnectTimeout))
	if err != nil {
		return fmt.Errorf("cannot connect to %s:%s: %w", host, port, err)
	}
	tc := conn.(*net.TCPConn)
	return proxyStream(tc, os.Stdin, os.Stdout)
}

func proxyStream(tc *net.TCPConn, input io.ReadCloser, output io.Writer) error {
	defer func() { _ = tc.Close() }()
	defer func() { _ = input.Close() }()
	// EOF from the client only closes the outgoing half. The server may wait
	// for that EOF before sending its response, which must be drained in full.
	watch := sessionlimit.Start(func() {
		_ = tc.Close()
		_ = input.Close()
		if closer, ok := output.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	defer watch.Stop()
	stream := &sessionlimit.Conn{Conn: tc, Watch: watch}
	inputDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(stream, input)
		inputDone <- err
		if err != nil {
			_ = tc.Close()
			return
		}
		_ = tc.CloseWrite()
	}()
	_, outputErr := io.Copy(output, stream)
	select {
	case err := <-inputDone:
		if err != nil {
			return fmt.Errorf("TCP proxy upload: %w", err)
		}
	default:
		// Remote EOF must also release a client that is still waiting to send.
	}
	return outputErr
}
