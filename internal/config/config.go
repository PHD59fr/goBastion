package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

// Config holds all configurable parameters for goBastion.
// Defaults match the previous hardcoded values for backward compatibility.
type Config struct {
	Database DatabaseConfig `json:"database" toml:"database"`
	Paths    PathsConfig    `json:"paths" toml:"paths"`
	SSH      SSHConfig      `json:"ssh" toml:"ssh"`
	MFA      MFAConfig      `json:"mfa" toml:"mfa"`
	TOTP     TOTPConfig     `json:"totp" toml:"totp"`
	Proxy    ProxyConfig    `json:"proxy" toml:"proxy"`
	Sync     SyncConfig     `json:"sync" toml:"sync"`
	Account  AccountConfig  `json:"account" toml:"account"`
	DBExport DBExportConfig `json:"db_export" toml:"db_export"`
	Security SecurityConfig `json:"security" toml:"security"`
}

type DatabaseConfig struct {
	Driver             string        `json:"driver" toml:"driver"`
	DSN                string        `json:"dsn" toml:"dsn"`
	MaxOpenConns       int           `json:"max_open_conns" toml:"max_open_conns"`
	MaxIdleConns       int           `json:"max_idle_conns" toml:"max_idle_conns"`
	ConnMaxLifetime    time.Duration `json:"conn_max_lifetime" toml:"conn_max_lifetime"`
	SlowQueryThreshold time.Duration `json:"slow_query_threshold" toml:"slow_query_threshold"`
	SQLite             SQLiteConfig  `json:"sqlite" toml:"sqlite"`
}

type SQLiteConfig struct {
	CacheSize   int `json:"cache_size" toml:"cache_size"`
	BusyTimeout int `json:"busy_timeout" toml:"busy_timeout"` // milliseconds
}

type PathsConfig struct {
	HomeBaseDir   string `json:"home_base_dir" toml:"home_base_dir"`
	TtyrecDir     string `json:"ttyrec_dir" toml:"ttyrec_dir"`
	LogFile       string `json:"log_file" toml:"log_file"`
	DbDir         string `json:"db_dir" toml:"db_dir"`
	DbConfFile    string `json:"db_conf_file" toml:"db_conf_file"`
	SshHostKeyDir string `json:"ssh_host_key_dir" toml:"ssh_host_key_dir"`
}

type SSHConfig struct {
	DefaultPort    int64         `json:"default_port" toml:"default_port"`
	HostKeyTTL     time.Duration `json:"host_key_ttl" toml:"host_key_ttl"`
	KeyscanTimeout time.Duration `json:"keyscan_timeout" toml:"keyscan_timeout"`
}

type MFAConfig struct {
	MaxAttempts int           `json:"max_attempts" toml:"max_attempts"`
	BackoffBase time.Duration `json:"backoff_base" toml:"backoff_base"`
}

type TOTPConfig struct {
	BackupCodesCount int `json:"backup_codes_count" toml:"backup_codes_count"`
	BackupCodeLength int `json:"backup_code_length" toml:"backup_code_length"`
}

type ProxyConfig struct {
	TCPConnectTimeout time.Duration `json:"tcp_connect_timeout" toml:"tcp_connect_timeout"`
	SFTPDialTimeout   time.Duration `json:"sftp_dial_timeout" toml:"sftp_dial_timeout"`
	SFTPSSHTimeout    time.Duration `json:"sftp_ssh_timeout" toml:"sftp_ssh_timeout"`
}

type SyncConfig struct {
	IntervalSeconds int `json:"interval_seconds" toml:"interval_seconds"`
}

type AccountConfig struct {
	MaxInactiveDays int `json:"max_inactive_days" toml:"max_inactive_days"` // 0 = disabled
}

type DBExportConfig struct {
	Argon2Time    uint32 `json:"argon2_time" toml:"argon2_time"`
	Argon2Memory  uint32 `json:"argon2_memory" toml:"argon2_memory"`
	Argon2Threads uint8  `json:"argon2_threads" toml:"argon2_threads"`
	Argon2KeyLen  uint32 `json:"argon2_key_len" toml:"argon2_key_len"`
	ImportMaxSize int64  `json:"import_max_size" toml:"import_max_size"` // bytes
}

type SecurityConfig struct {
	DefaultWildcardUsername string `json:"default_wildcard_username" toml:"default_wildcard_username"`
}

// Bootstrap holds env-only config that cannot be changed at runtime.
type Bootstrap struct {
	DBDriver   string
	DBDSN      string
	InstanceID string
}

var (
	global      atomic.Pointer[Config]
	defaults    *Config
	globalOnce  sync.Once
	globalBoot  atomic.Pointer[Bootstrap]
	configMu    sync.RWMutex // protects Reload and LoadFromDB serialization
)

// defaultConfig returns the Config with all defaults matching the previous
// hardcoded values. This ensures backward compatibility when no config file
// is provided.
func defaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Driver:             "sqlite",
			DSN:                "",
			MaxOpenConns:       10,
			MaxIdleConns:       5,
			ConnMaxLifetime:    5 * time.Minute,
			SlowQueryThreshold: time.Second,
			SQLite: SQLiteConfig{
				CacheSize:   2000,
				BusyTimeout: 20000,
			},
		},
		Paths: PathsConfig{
			HomeBaseDir:   "/home",
			TtyrecDir:     "/app/ttyrec",
			LogFile:       "/goBastion.log",
			DbDir:         "/var/lib/goBastion",
			DbConfFile:    "/run/gobastion/db.conf",
			SshHostKeyDir: "/etc/ssh",
		},
		SSH: SSHConfig{
			DefaultPort:    22,
			HostKeyTTL:     24 * time.Hour,
			KeyscanTimeout: 5 * time.Second,
		},
		MFA: MFAConfig{
			MaxAttempts: 3,
			BackoffBase: time.Second,
		},
		TOTP: TOTPConfig{
			BackupCodesCount: 10,
			BackupCodeLength: 8,
		},
		Proxy: ProxyConfig{
			TCPConnectTimeout: 5 * time.Second,
			SFTPDialTimeout:   15 * time.Second,
			SFTPSSHTimeout:    15 * time.Second,
		},
		Sync: SyncConfig{
			IntervalSeconds: 300,
		},
		Account: AccountConfig{
			MaxInactiveDays: 0,
		},
		DBExport: DBExportConfig{
			Argon2Time:    3,
			Argon2Memory:  64 * 1024,
			Argon2Threads: 2,
			Argon2KeyLen:  32,
			ImportMaxSize: 512 * 1024 * 1024,
		},
		Security: SecurityConfig{
			DefaultWildcardUsername: "root",
		},
	}
}

// Load reads bootstrap configuration from environment variables only.
// DB_DRIVER, DB_DSN, and INSTANCE_ID are read here. The full config
// is loaded later from the database via LoadFromDB.
func Load() *Config {
	globalOnce.Do(func() {
		// Store immutable defaults for diff display.
		defaults = defaultConfig()

		// Start with defaults.
		cfg := defaultConfig()

		// Apply env var overrides for backward compatibility.
		applyEnvOverrides(cfg)

		// Apply SQLite-specific defaults when driver is sqlite.
		if cfg.Database.Driver == "sqlite" || cfg.Database.Driver == "" {
			cfg.Database.MaxOpenConns = 1
			cfg.Database.MaxIdleConns = 1
			// Also update defaults so diff comparison is apples-to-apples.
			defaults.Database.MaxOpenConns = 1
			defaults.Database.MaxIdleConns = 1
		}

		global.Store(cfg)

		// Determine instance identity.
		instanceID := resolveInstanceID()
		boot := &Bootstrap{
			DBDriver:   cfg.Database.Driver,
			DBDSN:      cfg.Database.DSN,
			InstanceID: instanceID,
		}
		globalBoot.Store(boot)

		slog.Info("config_bootstrap_loaded",
			slog.String("instance_id", instanceID),
			slog.String("db_driver", boot.DBDriver),
		)
	})
	return global.Load()
}

// LoadFromDB reads the full configuration from the bastion_instances table
// for the current instance and stores it in memory. This is called after
// the database connection is established.
func LoadFromDB(db *gorm.DB) error {
	configMu.Lock()
	defer configMu.Unlock()

	boot := globalBoot.Load()
	if boot == nil {
		return fmt.Errorf("bootstrap not loaded: call Load() first")
	}

	cfg, err := readConfigFromDB(db, boot.InstanceID)
	if err != nil {
		slog.Warn("config_db_load_failed",
			slog.String("instance_id", boot.InstanceID),
			slog.String("error", err.Error()),
			slog.String("msg", "using bootstrap defaults"),
		)
		return err
	}

	// Re-apply bootstrap values (DB connection params are never overridden by DB).
	cfg.Database.Driver = boot.DBDriver
	cfg.Database.DSN = boot.DBDSN

	// Re-apply SQLite pool constraints.
	if cfg.Database.Driver == "sqlite" || cfg.Database.Driver == "" {
		cfg.Database.MaxOpenConns = 1
		cfg.Database.MaxIdleConns = 1
	}

	global.Store(cfg)
	slog.Info("config_loaded_from_db", slog.String("instance_id", boot.InstanceID))
	return nil
}

// Reload re-reads the config from the database. Called periodically by the
// sync loop to pick up admin changes.
func Reload(db *gorm.DB) {
	configMu.Lock()
	defer configMu.Unlock()

	boot := globalBoot.Load()
	if boot == nil {
		return
	}

	cfg, err := readConfigFromDB(db, boot.InstanceID)
	if err != nil {
		slog.Warn("config_reload_failed", slog.String("error", err.Error()))
		return
	}

	cfg.Database.Driver = boot.DBDriver
	cfg.Database.DSN = boot.DBDSN

	if cfg.Database.Driver == "sqlite" || cfg.Database.Driver == "" {
		cfg.Database.MaxOpenConns = 1
		cfg.Database.MaxIdleConns = 1
	}

	global.Store(cfg)
	slog.Debug("config_reloaded", slog.String("instance_id", boot.InstanceID))
}

// EnsureInstance creates the default config row for the instance if it doesn't exist.
func EnsureInstance(db *gorm.DB) error {
	boot := globalBoot.Load()
	if boot == nil {
		return fmt.Errorf("bootstrap not loaded")
	}

	cfg := defaultConfig()
	cfg.Database.Driver = ""
	cfg.Database.DSN = ""
	jsonData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal default config: %w", err)
	}

	result := db.Exec(`
		INSERT INTO bastion_instances (instance_id, role, config, created_at, updated_at)
		VALUES (?, 'master', ?, datetime('now'), datetime('now'))
		ON CONFLICT(instance_id) DO NOTHING
	`, boot.InstanceID, string(jsonData))
	if result.Error != nil {
		return fmt.Errorf("ensure instance: %w", result.Error)
	}
	if result.RowsAffected > 0 {
		slog.Info("config_instance_created",
			slog.String("instance_id", boot.InstanceID),
			slog.String("role", "master"),
		)
	}
	return nil
}

// SaveConfig writes the given config back to the DB for the current instance.
func SaveConfig(db *gorm.DB, cfg *Config) error {
	configMu.Lock()
	defer configMu.Unlock()

	boot := globalBoot.Load()
	if boot == nil {
		return fmt.Errorf("bootstrap not loaded")
	}

	// Strip bootstrap-only fields before saving.
	saveCfg := *cfg
	saveCfg.Database.Driver = ""
	saveCfg.Database.DSN = ""

	jsonData, err := json.MarshalIndent(saveCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	result := db.Model(&struct {
		InstanceID string `gorm:"primaryKey"`
	}{}).Table("bastion_instances").
		Where("instance_id = ?", boot.InstanceID).
		Update("config", string(jsonData))
	if result.Error != nil {
		return fmt.Errorf("save config: %w", result.Error)
	}

	global.Store(cfg)
	slog.Info("config_saved", slog.String("instance_id", boot.InstanceID))
	return nil
}

// readConfigFromDB reads the config JSON from the bastion_instances table.
func readConfigFromDB(db *gorm.DB, instanceID string) (*Config, error) {
	type row struct {
		Config string
	}
	var r row
	if err := db.Table("bastion_instances").Where("instance_id = ?", instanceID).Select("config").First(&r).Error; err != nil {
		return nil, fmt.Errorf("query instance %s: %w", instanceID, err)
	}
	if r.Config == "" {
		return defaultConfig(), nil
	}

	cfg := defaultConfig()
	if err := json.Unmarshal([]byte(r.Config), cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config for %s: %w", instanceID, err)
	}
	return cfg, nil
}

// resolveInstanceID determines the instance identity from env or hostname.
func resolveInstanceID() string {
	if v := os.Getenv("INSTANCE_ID"); v != "" {
		return v
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "master"
}

// applyEnvOverrides sets config values from environment variables when they
// are set. This preserves backward compatibility with existing deployments.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("DB_DRIVER"); v != "" {
		cfg.Database.Driver = v
	}
	if v := os.Getenv("DB_DSN"); v != "" {
		cfg.Database.DSN = v
	}
}

// Get returns the loaded configuration. Always calls Load() which is
// idempotent via sync.Once, avoiding data races on the global pointer.
func Get() *Config {
	return Load()
}

// GetDefaults returns the immutable default config (for diff display).
func GetDefaults() *Config {
	return defaults
}

// InstanceID returns the current instance identifier.
func InstanceID() string {
	if b := globalBoot.Load(); b != nil {
		return b.InstanceID
	}
	return "unknown"
}

// GetBootstrap returns the bootstrap configuration (env vars).
func GetBootstrap() *Bootstrap {
	if b := globalBoot.Load(); b != nil {
		return b
	}
	return &Bootstrap{}
}

// ConfigEntry represents one config key for the table display.
type ConfigEntry struct {
	Section  string
	Key      string
	Value    string
	Default  string
	Modified bool
}

// ConfigDiff returns all config entries with current value, default, and
// whether the value has been modified from default.
func ConfigDiff() []ConfigEntry {
	cfg := Get()
	def := defaults
	if def == nil {
		def = defaultConfig()
	}

	var entries []ConfigEntry

	add := func(section, key, current, defVal string) {
		entries = append(entries, ConfigEntry{
			Section:  section,
			Key:      key,
			Value:    current,
			Default:  defVal,
			Modified: current != defVal,
		})
	}

	// Database
	add("database", "max_open_conns", fmt.Sprintf("%d", cfg.Database.MaxOpenConns), fmt.Sprintf("%d", def.Database.MaxOpenConns))
	add("database", "max_idle_conns", fmt.Sprintf("%d", cfg.Database.MaxIdleConns), fmt.Sprintf("%d", def.Database.MaxIdleConns))
	add("database", "conn_max_lifetime", cfg.Database.ConnMaxLifetime.String(), def.Database.ConnMaxLifetime.String())
	add("database", "slow_query_threshold", cfg.Database.SlowQueryThreshold.String(), def.Database.SlowQueryThreshold.String())
	add("database", "sqlite.cache_size", fmt.Sprintf("%d", cfg.Database.SQLite.CacheSize), fmt.Sprintf("%d", def.Database.SQLite.CacheSize))
	add("database", "sqlite.busy_timeout", fmt.Sprintf("%d", cfg.Database.SQLite.BusyTimeout), fmt.Sprintf("%d", def.Database.SQLite.BusyTimeout))

	// Paths
	add("paths", "home_base_dir", cfg.Paths.HomeBaseDir, def.Paths.HomeBaseDir)
	add("paths", "ttyrec_dir", cfg.Paths.TtyrecDir, def.Paths.TtyrecDir)
	add("paths", "log_file", cfg.Paths.LogFile, def.Paths.LogFile)
	add("paths", "db_dir", cfg.Paths.DbDir, def.Paths.DbDir)
	add("paths", "ssh_host_key_dir", cfg.Paths.SshHostKeyDir, def.Paths.SshHostKeyDir)

	// SSH
	add("ssh", "default_port", fmt.Sprintf("%d", cfg.SSH.DefaultPort), fmt.Sprintf("%d", def.SSH.DefaultPort))
	add("ssh", "host_key_ttl", cfg.SSH.HostKeyTTL.String(), def.SSH.HostKeyTTL.String())
	add("ssh", "keyscan_timeout", cfg.SSH.KeyscanTimeout.String(), def.SSH.KeyscanTimeout.String())

	// MFA
	add("mfa", "max_attempts", fmt.Sprintf("%d", cfg.MFA.MaxAttempts), fmt.Sprintf("%d", def.MFA.MaxAttempts))
	add("mfa", "backoff_base", cfg.MFA.BackoffBase.String(), def.MFA.BackoffBase.String())

	// TOTP
	add("totp", "backup_codes_count", fmt.Sprintf("%d", cfg.TOTP.BackupCodesCount), fmt.Sprintf("%d", def.TOTP.BackupCodesCount))
	add("totp", "backup_code_length", fmt.Sprintf("%d", cfg.TOTP.BackupCodeLength), fmt.Sprintf("%d", def.TOTP.BackupCodeLength))

	// Proxy
	add("proxy", "tcp_connect_timeout", cfg.Proxy.TCPConnectTimeout.String(), def.Proxy.TCPConnectTimeout.String())
	add("proxy", "sftp_dial_timeout", cfg.Proxy.SFTPDialTimeout.String(), def.Proxy.SFTPDialTimeout.String())
	add("proxy", "sftp_ssh_timeout", cfg.Proxy.SFTPSSHTimeout.String(), def.Proxy.SFTPSSHTimeout.String())

	// Sync
	add("sync", "interval_seconds", fmt.Sprintf("%d", cfg.Sync.IntervalSeconds), fmt.Sprintf("%d", def.Sync.IntervalSeconds))

	// Account
	add("account", "max_inactive_days", fmt.Sprintf("%d", cfg.Account.MaxInactiveDays), fmt.Sprintf("%d", def.Account.MaxInactiveDays))

	// DBExport
	add("db_export", "argon2_time", fmt.Sprintf("%d", cfg.DBExport.Argon2Time), fmt.Sprintf("%d", def.DBExport.Argon2Time))
	add("db_export", "argon2_memory", fmt.Sprintf("%d", cfg.DBExport.Argon2Memory), fmt.Sprintf("%d", def.DBExport.Argon2Memory))
	add("db_export", "argon2_threads", fmt.Sprintf("%d", cfg.DBExport.Argon2Threads), fmt.Sprintf("%d", def.DBExport.Argon2Threads))
	add("db_export", "argon2_key_len", fmt.Sprintf("%d", cfg.DBExport.Argon2KeyLen), fmt.Sprintf("%d", def.DBExport.Argon2KeyLen))
	add("db_export", "import_max_size", fmt.Sprintf("%d", cfg.DBExport.ImportMaxSize), fmt.Sprintf("%d", def.DBExport.ImportMaxSize))

	// Security
	add("security", "default_wildcard_username", cfg.Security.DefaultWildcardUsername, def.Security.DefaultWildcardUsername)

	return entries
}

// SetForTesting replaces the global config. Only for use in tests.
func SetForTesting(cfg *Config) {
	global.Store(cfg)
}

// ResetForTesting clears the global config and sync.Once so the next call
// to Load() re-reads. Only for use in tests.
func ResetForTesting() {
	global.Store(nil)
	defaults = nil
	globalOnce = sync.Once{}
}
