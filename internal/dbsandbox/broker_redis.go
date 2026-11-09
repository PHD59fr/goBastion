package dbsandbox

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/utils/validation"
)

func (b *broker) redis(native net.Conn) error {
	ctx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
	defer cancel()
	raw, err := b.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	upstream := tls.Client(raw, b.tlsConfig())
	if err := upstream.HandshakeContext(ctx); err != nil {
		return err
	}
	r := bufio.NewReader(upstream)
	if parts, explicit := redisAuthCommand(b.user, b.password); explicit {
		if err := writeRedisCommand(upstream, parts...); err != nil {
			return err
		}
		budget := 16 * 1024 * 1024
		result, err := readRedisValue(r, &budget, 0)
		if err != nil {
			return err
		}
		if result.kind != '+' || string(result.text) != "OK" {
			return fmt.Errorf("redis authentication rejected")
		}
	}
	// Select the configured logical database before the client starts. The
	// native client repeats the selection for its prompt, but the broker's
	// selection is the fail-closed gate: if the server or ACL refuses it, the
	// session never reaches the client on database 0.
	if parts, explicit, err := redisSelectCommand(b.database); err != nil {
		return err
	} else if explicit {
		if err := writeRedisCommand(upstream, parts...); err != nil {
			return err
		}
		budget := 16 * 1024 * 1024
		result, err := readRedisValue(r, &budget, 0)
		if err != nil {
			return err
		}
		if result.kind != '+' || string(result.text) != "OK" {
			return fmt.Errorf("redis database selection rejected")
		}
	}
	// Redis administrative commands can reveal credentials stored by the DB
	// itself (e.g. CONFIG GET requirepass). Discover flags, including aliases
	// and subcommands, instead of relying on a bypassable name blacklist.
	if err := writeRedisCommand(upstream, "COMMAND"); err != nil {
		return err
	}
	budget := 16 * 1024 * 1024
	commands, err := readRedisValue(r, &budget, 0)
	if err != nil {
		return err
	}
	if commands.kind != '*' {
		return fmt.Errorf("redis COMMAND permission is required for protected sessions")
	}
	var names []string
	for _, command := range commands.children {
		if len(command.children) >= 3 {
			names = append(names, strings.ToLower(string(command.children[0].text)))
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("redis command metadata is empty")
	}
	// COMMAND lists canonical names even after rename-command. Resolve those
	// names again so an administrative/identity command renamed to GET or PING
	// cannot inherit the permission of the original command with that name.
	if err := writeRedisCommand(upstream, append([]string{"COMMAND", "INFO"}, names...)...); err != nil {
		return err
	}
	budget = 16 * 1024 * 1024
	resolved, err := readRedisValue(r, &budget, 0)
	if err != nil {
		return err
	}
	if resolved.kind != '*' || len(resolved.children) != len(names) {
		return fmt.Errorf("redis COMMAND INFO permission is required for protected sessions")
	}
	allowed := make(map[string]bool, len(names))
	for i, name := range names {
		allowed[name] = redisCommandAllowed(name, resolved.children[i])
	}
	_ = native.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	stop := context.AfterFunc(b.ctx, func() { _ = native.Close(); _ = upstream.Close() })
	defer stop()
	done := make(chan error, 1)
	go func() {
		err := copyRedisCommands(upstream, bufio.NewReader(native), allowed)
		_ = native.Close()
		_ = upstream.Close()
		done <- err
	}()
	_, outputErr := io.Copy(native, r)
	_ = native.Close()
	_ = upstream.Close()
	if inputErr := <-done; inputErr != nil && inputErr != io.EOF {
		return inputErr
	}
	return outputErr
}

// redisAuthCommand selects the configured ACL identity even when no password
// is stored. A nopass user still requires AUTH to leave the default identity,
// which may be more privileged. An empty password is sent explicitly so the
// broker can fail closed if the server does not accept that identity.
func redisAuthCommand(user, password string) ([]string, bool) {
	if user == "" && password == "" {
		return nil, false
	}
	parts := []string{"AUTH"}
	if user != "" {
		parts = append(parts, user)
	}
	parts = append(parts, password)
	return parts, true
}

// redisSelectCommand returns the broker's initial database selection. An empty
// value keeps the server default instead of forcing database 0 explicitly.
func redisSelectCommand(database string) ([]string, bool, error) {
	index, err := validation.NormalizeRedisDatabase(database)
	if err != nil {
		return nil, false, err
	}
	if index == "" {
		return nil, false, nil
	}
	return []string{"SELECT", index}, true, nil
}

func redisCommandAllowed(name string, metadata redisValue) bool {
	// AUTH and RESET can change the identity selected by the supervisor.
	return name != "auth" && name != "reset" && len(metadata.children) >= 3 &&
		strings.EqualFold(string(metadata.children[0].text), name) && !redisAdmin(metadata)
}

func copyRedisCommands(dst io.Writer, src *bufio.Reader, allowed map[string]bool) error {
	for {
		line, err := redisLine(src)
		if err != nil {
			return err
		}
		if len(line) < 2 || line[0] != '*' {
			return fmt.Errorf("redis clients must use RESP arrays")
		}
		count, err := strconv.Atoi(string(line[1:]))
		if err != nil || count < 1 || count > 1000000 {
			return fmt.Errorf("invalid Redis argument count")
		}
		length, err := redisBulkLength(src)
		if err != nil || length < 1 || length > 128 {
			return fmt.Errorf("invalid Redis command name")
		}
		name := make([]byte, length+2)
		if _, err := io.ReadFull(src, name); err != nil {
			return err
		}
		if name[length] != '\r' || name[length+1] != '\n' {
			return fmt.Errorf("invalid Redis command terminator")
		}
		command := strings.ToLower(string(name[:length]))
		if !allowed[command] || (command == "hello" && count > 2) {
			return fmt.Errorf("redis administrative or unknown command denied")
		}
		if _, err := fmt.Fprintf(dst, "*%d\r\n$%d\r\n", count, length); err != nil {
			return err
		}
		if _, err := dst.Write(name); err != nil {
			return err
		}
		for i := 1; i < count; i++ {
			n, err := redisBulkLength(src)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(dst, "$%d\r\n", n); err != nil {
				return err
			}
			if _, err := io.CopyN(dst, src, int64(n)); err != nil {
				return err
			}
			var ending [2]byte
			if _, err := io.ReadFull(src, ending[:]); err != nil {
				return err
			}
			if ending != [2]byte{'\r', '\n'} {
				return fmt.Errorf("invalid Redis bulk terminator")
			}
			if _, err := dst.Write(ending[:]); err != nil {
				return err
			}
		}
	}
}

func redisBulkLength(r *bufio.Reader) (int, error) {
	line, err := redisLine(r)
	if err != nil {
		return 0, err
	}
	if len(line) < 2 || line[0] != '$' {
		return 0, fmt.Errorf("invalid Redis bulk value")
	}
	n, err := strconv.Atoi(string(line[1:]))
	if err != nil || n < 0 || n > 512*1024*1024 {
		return 0, fmt.Errorf("invalid Redis bulk length")
	}
	return n, nil
}

func redisLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, fmt.Errorf("invalid Redis line")
	}
	return line[:len(line)-2], nil
}

func writeRedisCommand(w io.Writer, parts ...string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(parts)); err != nil {
		return err
	}
	for _, part := range parts {
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(part), part); err != nil {
			return err
		}
	}
	return nil
}

type redisValue struct {
	kind     byte
	text     []byte
	children []redisValue
}

func readRedisValue(r *bufio.Reader, budget *int, depth int) (redisValue, error) {
	if depth > 32 {
		return redisValue{}, fmt.Errorf("redis metadata is too deeply nested")
	}
	line, err := redisLine(r)
	if err != nil {
		return redisValue{}, err
	}
	if len(line) < 1 {
		return redisValue{}, fmt.Errorf("empty Redis metadata")
	}
	*budget -= len(line) + 2
	if *budget < 0 {
		return redisValue{}, fmt.Errorf("oversized Redis metadata")
	}
	v := redisValue{kind: line[0]}
	switch v.kind {
	case '+', '-', ':':
		v.text = append([]byte(nil), line[1:]...)
	case '$':
		n, err := strconv.Atoi(string(line[1:]))
		if err != nil || n < -1 || n > *budget {
			return v, fmt.Errorf("invalid Redis metadata length")
		}
		if n == -1 {
			return v, nil
		}
		data := make([]byte, n+2)
		if _, err := io.ReadFull(r, data); err != nil {
			return v, err
		}
		if data[n] != '\r' || data[n+1] != '\n' {
			return v, fmt.Errorf("invalid Redis metadata terminator")
		}
		v.text = data[:n]
		*budget -= n + 2
	case '*':
		n, err := strconv.Atoi(string(line[1:]))
		if err != nil || n < -1 || n > *budget/3 {
			return v, fmt.Errorf("invalid Redis metadata array")
		}
		for i := 0; i < n; i++ {
			child, err := readRedisValue(r, budget, depth+1)
			if err != nil {
				return v, err
			}
			v.children = append(v.children, child)
		}
	default:
		return v, fmt.Errorf("invalid Redis metadata type")
	}
	return v, nil
}

func redisAdmin(v redisValue) bool {
	if strings.EqualFold(string(v.text), "admin") {
		return true
	}
	for _, child := range v.children {
		if redisAdmin(child) {
			return true
		}
	}
	return false
}
