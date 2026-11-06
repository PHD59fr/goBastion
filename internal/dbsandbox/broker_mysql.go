package dbsandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	mysqlclient "github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/tidb/pkg/parser/charset"
)

const mysqlCapabilities = mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_LONG_FLAG |
	mysql.CLIENT_CONNECT_WITH_DB | mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_TRANSACTIONS |
	mysql.CLIENT_SECURE_CONNECTION | mysql.CLIENT_PLUGIN_AUTH | mysql.CLIENT_MULTI_STATEMENTS |
	mysql.CLIENT_MULTI_RESULTS | mysql.CLIENT_PS_MULTI_RESULTS

func (b *broker) mysql(native net.Conn) error {
	ctx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
	defer cancel()
	upstream, err := mysqlclient.ConnectWithDialer(ctx, "tcp", b.address, b.user, b.password, b.database,
		func(ctx context.Context, _, _ string) (net.Conn, error) { return b.dial(ctx) },
		func(c *mysqlclient.Conn) error {
			c.SetTLSConfig(b.tlsConfig())
			c.ReadTimeout, c.WriteTimeout = 15*time.Second, 15*time.Second
			c.UnsetCapability(mysql.CLIENT_DEPRECATE_EOF | mysql.CLIENT_QUERY_ATTRIBUTES)
			if err := c.SetCollation("utf8mb4_general_ci"); err != nil {
				return err
			}
			for _, flag := range []uint32{mysql.CLIENT_MULTI_STATEMENTS, mysql.CLIENT_MULTI_RESULTS, mysql.CLIENT_PS_MULTI_RESULTS} {
				if err := c.SetCapability(flag); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		_ = mysqlError(native, 0, "Upstream TLS verification or authentication failed; check the bastion log")
		return err
	}
	defer func() { _ = upstream.Close() }()
	var salt [20]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	greeting := []byte{10}
	greeting = append(greeting, upstream.GetServerVersion()...)
	greeting = append(greeting, 0)
	greeting = binary.LittleEndian.AppendUint32(greeting, upstream.GetConnectionID())
	greeting = append(greeting, salt[:8]...)
	greeting = append(greeting, 0)
	greeting = binary.LittleEndian.AppendUint16(greeting, uint16(mysqlCapabilities&0xffff))
	greeting = append(greeting, 45) // utf8mb4_general_ci
	greeting = binary.LittleEndian.AppendUint16(greeting, mysql.SERVER_STATUS_AUTOCOMMIT)
	greeting = binary.LittleEndian.AppendUint16(greeting, uint16(mysqlCapabilities>>16))
	greeting = append(greeting, 21)
	greeting = append(greeting, make([]byte, 10)...)
	greeting = append(greeting, salt[8:]...)
	greeting = append(greeting, 0)
	greeting = append(greeting, "mysql_native_password\x00"...)
	if err := writeMySQLPacket(native, 0, greeting); err != nil {
		return err
	}
	response, sequence, err := readMySQLPacket(native)
	if err != nil {
		return err
	}
	user, database, err := mysqlLogin(response)
	if err != nil || user != b.user {
		_ = mysqlError(native, sequence+1, "This stream is bound to the selected bastion account")
		return fmt.Errorf("invalid client identity in MySQL broker handshake")
	}
	if database != "" && database != b.database {
		if err := upstream.UseDB(database); err != nil {
			_ = mysqlError(native, sequence+1, "Database selection denied by upstream server")
			return err
		}
	}
	characterSet, _, err := charset.GetCharsetInfoByID(int(response[8]))
	if err != nil {
		_ = mysqlError(native, sequence+1, "Unsupported client character set")
		return err
	}
	if err := upstream.SetCharset(characterSet); err != nil {
		_ = mysqlError(native, sequence+1, "Client character set rejected by upstream")
		return err
	}
	// Both legs use the classic protocol without compression, query attributes
	// or deprecated EOF packets. No SQL parser or credential-bearing client is needed.
	if err := writeMySQLPacket(native, sequence+1, []byte{0, 0, 0, 2, 0, 0, 0}); err != nil {
		return err
	}
	return relayWithUpload(b.ctx, native, upstream.Conn.Conn, copyMySQLCommands)
}

// A raw COM_CHANGE_USER would bypass the identity selected by the supervisor.
// Stream packet bodies without buffering SQL results or large parameter data.
func copyMySQLCommands(dst io.Writer, src io.Reader) error {
	continuation := false
	var expected byte
	for {
		var header [4]byte
		if _, err := io.ReadFull(src, header[:]); err != nil {
			return err
		}
		n := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
		if (!continuation && header[3] != 0) || (continuation && header[3] != expected) {
			return fmt.Errorf("invalid MySQL command sequence")
		}
		remaining := n
		if !continuation && n > 0 {
			var command [1]byte
			if _, err := io.ReadFull(src, command[:]); err != nil {
				return err
			}
			if command[0] == mysql.COM_CHANGE_USER {
				return fmt.Errorf("MySQL account switching denied")
			}
			if _, err := dst.Write(header[:]); err != nil {
				return err
			}
			if _, err := dst.Write(command[:]); err != nil {
				return err
			}
			remaining--
		} else if _, err := dst.Write(header[:]); err != nil {
			return err
		}
		if _, err := io.CopyN(dst, src, int64(remaining)); err != nil {
			return err
		}
		continuation, expected = n == 0xffffff, header[3]+1
	}
}

func mysqlLogin(p []byte) (string, string, error) {
	if len(p) < 33 {
		return "", "", fmt.Errorf("short MySQL login")
	}
	flags := binary.LittleEndian.Uint32(p[:4])
	if flags&mysql.CLIENT_PROTOCOL_41 == 0 || flags&(mysql.CLIENT_SSL|mysql.CLIENT_COMPRESS|mysql.CLIENT_DEPRECATE_EOF|mysql.CLIENT_QUERY_ATTRIBUTES) != 0 {
		return "", "", fmt.Errorf("unsupported local MySQL capabilities")
	}
	p = p[32:]
	end := bytes.IndexByte(p, 0)
	if end < 0 {
		return "", "", fmt.Errorf("invalid MySQL username")
	}
	user := string(p[:end])
	p = p[end+1:]
	if len(p) == 0 {
		return "", "", fmt.Errorf("missing MySQL authentication field")
	}
	if flags&mysql.CLIENT_SECURE_CONNECTION != 0 {
		n := int(p[0])
		p = p[1:]
		if n > len(p) {
			return "", "", fmt.Errorf("invalid MySQL authentication length")
		}
		p = p[n:]
	} else {
		end = bytes.IndexByte(p, 0)
		if end < 0 {
			return "", "", fmt.Errorf("invalid MySQL authentication field")
		}
		p = p[end+1:]
	}
	if flags&mysql.CLIENT_CONNECT_WITH_DB != 0 {
		end = bytes.IndexByte(p, 0)
		if end < 0 {
			return "", "", fmt.Errorf("invalid database name")
		}
		return user, string(p[:end]), nil
	}
	return user, "", nil
}

func readMySQLPacket(conn net.Conn) ([]byte, byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, 0, err
	}
	n := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if n > 65536 {
		return nil, 0, fmt.Errorf("oversized MySQL handshake")
	}
	data := make([]byte, n)
	_, err := io.ReadFull(conn, data)
	return data, header[3], err
}

func writeMySQLPacket(conn io.Writer, sequence byte, body []byte) error {
	data := []byte{byte(len(body)), byte(len(body) >> 8), byte(len(body) >> 16), sequence}
	data = append(data, body...)
	_, err := conn.Write(data)
	return err
}

func mysqlError(conn net.Conn, sequence byte, message string) error {
	return writeMySQLPacket(conn, sequence, append([]byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}, message...))
}
