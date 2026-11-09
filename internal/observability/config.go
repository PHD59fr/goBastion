package observability

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Config struct {
	Enabled       bool
	ListenAddress string
	// Token is programmatic configuration, principally for embedding/tests. The
	// standalone root daemon loads only OBS_AUTH_TOKEN_FILE, never a token env var.
	Token            string
	DBTimeout        time.Duration
	ShutdownTimeout  time.Duration
	RecordingSpool   string
	PendingCollector func(context.Context) (PendingStats, error)
}

func DefaultConfig() Config {
	return Config{ListenAddress: "127.0.0.1:9090", DBTimeout: 2 * time.Second, ShutdownTimeout: 5 * time.Second}
}

// LoadConfigFromEnv defaults to disabled without touching any secret files.
// When enabled, only an explicit root-owned owner-readable secret file can
// configure the bearer credential. Errors never echo token contents or paths.
func LoadConfigFromEnv() (Config, error) {
	cfg := DefaultConfig()
	raw := os.Getenv("OBS_ENABLED")
	if raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return cfg, errors.New("invalid OBS_ENABLED")
		}
		cfg.Enabled = enabled
	}
	if !cfg.Enabled {
		return cfg, nil
	}
	if os.Getenv("OBS_AUTH_TOKEN") != "" {
		return cfg, errors.New("use OBS_AUTH_TOKEN_FILE for the observation credential")
	}
	if address := os.Getenv("OBS_LISTEN_ADDR"); address != "" {
		cfg.ListenAddress = address
	}
	if err := validateListenAddress(cfg.ListenAddress); err != nil {
		return cfg, err
	}
	for _, setting := range []struct {
		name    string
		target  *time.Duration
		maximum time.Duration
	}{
		{"OBS_DB_TIMEOUT", &cfg.DBTimeout, 10 * time.Second},
		{"OBS_SHUTDOWN_TIMEOUT", &cfg.ShutdownTimeout, 60 * time.Second},
	} {
		if value := os.Getenv(setting.name); value != "" {
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 || duration > setting.maximum {
				return cfg, errors.New("invalid observation timeout configuration")
			}
			*setting.target = duration
		}
	}
	token, err := readTokenFile(os.Getenv("OBS_AUTH_TOKEN_FILE"), 0)
	if err != nil {
		return cfg, err
	}
	cfg.Token = token
	cfg.RecordingSpool = os.Getenv("OBS_RECORDING_SPOOL")
	return cfg, nil
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("observation listener must be a numeric loopback IP and port")
	}
	ip := net.ParseIP(host)
	number, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || number < 1 || number > 65535 {
		return errors.New("observation listener must be a numeric loopback IP and port")
	}
	return nil
}

func validToken(token string) bool {
	if len(token) < 32 || len(token) > 512 {
		return false
	}
	for _, c := range []byte(token) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func readTokenFile(path string, expectedOwner uint32) (string, error) {
	invalid := errors.New("observation authentication requires a root-owned mode 0400 or 0600 regular token file")
	if path == "" {
		return "", invalid
	}
	// O_NONBLOCK prevents a FIFO from delaying startup; O_NOFOLLOW prevents a
	// final-component symlink from substituting an unrelated root-owned file.
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", invalid
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || (info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600) {
		return "", invalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedOwner {
		return "", invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, 515))
	if err != nil || len(data) > 514 {
		return "", invalid
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if !validToken(token) {
		return "", errors.New("invalid observation authentication token")
	}
	return token, nil
}

func tokenDigest(token string) [32]byte { return sha256.Sum256([]byte(token)) }
