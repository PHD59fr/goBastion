package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goBastion/internal/models"

	"gorm.io/gorm"
)

// Duration is a time.Duration that is (un)marshaled from/to a human-readable
// string (e.g. "30s", "5m") in JSON. A bare integer is interpreted as seconds.
// Numbers (the legacy nanosecond form) are still accepted on read for backward
// compatibility with config rows written before this type existed.
type Duration time.Duration

// MarshalJSON renders the duration as a string like "30s".
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts a duration string ("30s", "5m"), a bare integer
// (interpreted as seconds), or a legacy nanosecond number.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			*d = Duration(n) * Duration(time.Second)
			return nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string or number: %w", err)
	}
	*d = Duration(n)
	return nil
}

// String returns the time.Duration string form.
func (d Duration) String() string { return time.Duration(d).String() }

// Config holds all configurable parameters for goBastion.
// Defaults match the previous hardcoded values for backward compatibility.
type Config struct {
	// Database, Paths and DBExport are bootstrap/infra-only and must never be
	// persisted into the bastion_instances config row. They are derived from
	// defaults + env/db.conf at load time, so they cannot live in the DB (you
	// need them to connect in the first place). Only the app-specific sections
	// below are stored and editable via the DB.
	Database DatabaseConfig `json:"-"`
	Paths    PathsConfig    `json:"-"`
	SSH      SSHConfig      `json:"ssh" toml:"ssh"`
	MFA      MFAConfig      `json:"mfa" toml:"mfa"`
	TOTP     TOTPConfig     `json:"totp" toml:"totp"`
	Proxy    ProxyConfig    `json:"proxy" toml:"proxy"`
	Sync     SyncConfig     `json:"sync" toml:"sync"`
	Account  AccountConfig  `json:"account" toml:"account"`
	DBExport DBExportConfig `json:"-"`
	Security SecurityConfig `json:"security" toml:"security"`

	// Feature toggles. All default to enabled (true) unless noted, so existing
	// deployments keep working until an admin turns a feature off.
	SFTP        SFTPConfig        `json:"sftp" toml:"sftp"`
	SCP         SCPConfig         `json:"scp" toml:"scp"`
	RSync       RSyncConfig       `json:"rsync" toml:"rsync"`
	Mosh        MoshConfig        `json:"mosh" toml:"mosh"`
	Realms      RealmsConfig      `json:"realms" toml:"realms"`
	PIV         PIVConfig         `json:"pivs" toml:"pivs"`
	GuestAccess GuestAccessConfig `json:"guest_access" toml:"guest_access"`
	Interactive InteractiveConfig `json:"interactive" toml:"interactive"`

	// Modes (default off unless noted).
	Readonly     ReadonlyConfig     `json:"readonly" toml:"readonly"`
	Maintenance  MaintenanceConfig  `json:"maintenance" toml:"maintenance"`
	RequireMFA   RequireMFAConfig   `json:"require_mfa" toml:"require_mfa"`
	ForceOSHOnly ForceOSHOnlyConfig `json:"force_osh_only" toml:"force_osh_only"`

	// Recording + session limits.
	TTYRec  TTYRecConfig       `json:"ttyrec" toml:"ttyrec"`
	Session SessionLimitsConfig `json:"session" toml:"session"`

	// Self-service / admin sub-features.
	SelfIngress      SelfIngressConfig      `json:"self_ingress" toml:"self_ingress"`
	EgressKey        EgressKeyConfig        `json:"egress_key" toml:"egress_key"`
	TTYPlay          TTYPlayConfig          `json:"tty_play" toml:"tty_play"`
	AliasSelf        AliasSelfConfig        `json:"alias_self" toml:"alias_self"`
	AliasGroup       AliasGroupConfig       `json:"alias_group" toml:"alias_group"`
	Groups           GroupsConfig           `json:"groups" toml:"groups"`
	RestrictedGrants RestrictedGrantsConfig `json:"restricted_grants" toml:"restricted_grants"`
	RestrictedCmds   RestrictedCmdsConfig   `json:"restricted_cmds" toml:"restricted_cmds"`
	KnownHosts       KnownHostsConfig       `json:"known_hosts" toml:"known_hosts"`
	SelfMFA          SelfMFAConfig          `json:"self_mfa" toml:"self_mfa"`
	SelfPassword     SelfPasswordConfig     `json:"self_password" toml:"self_password"`
	BackupCodes      BackupCodesConfig      `json:"backup_codes" toml:"backup_codes"`

	// Connection policy.
	DenyRootTarget DenyRootTargetConfig `json:"deny_root_target" toml:"deny_root_target"`
}

type DatabaseConfig struct {
	// Driver and DSN are bootstrap-only (taken from env / db.conf) and must
	// never be persisted into the bastion_instances config row. They are
	// re-applied from the bootstrap after loading.
	Driver string `json:"-"`
	DSN    string `json:"-"`
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
	Enabled        bool     `json:"enabled" toml:"enabled"`                                  // false = block outgoing SSH (SFTP/SCP still allowed)
	DefaultPort    int64    `json:"default_port" toml:"default_port"`
	HostKeyTTL     Duration `json:"host_key_ttl" toml:"host_key_ttl"`
	KeyscanTimeout Duration `json:"keyscan_timeout" toml:"keyscan_timeout"`
}

type MFAConfig struct {
	MaxAttempts int     `json:"max_attempts" toml:"max_attempts"`
	BackoffBase Duration `json:"backoff_base" toml:"backoff_base"`
}

type TOTPConfig struct {
	BackupCodesCount int `json:"backup_codes_count" toml:"backup_codes_count"`
	BackupCodeLength int `json:"backup_code_length" toml:"backup_code_length"`
}

type ProxyConfig struct {
	TCPConnectTimeout Duration `json:"tcp_connect_timeout" toml:"tcp_connect_timeout"`
	SFTPDialTimeout   Duration `json:"sftp_dial_timeout" toml:"sftp_dial_timeout"`
	SFTPSSHTimeout    Duration `json:"sftp_ssh_timeout" toml:"sftp_ssh_timeout"`
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

// The following structs are simple feature toggles. Enabled defaults to true
// (features on) so existing deployments are unaffected; mode/policy toggles
// default to false (off).

type SFTPConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type SCPConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type RSyncConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type MoshConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type RealmsConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type PIVConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type GuestAccessConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type InteractiveConfig struct {
	Allow bool `json:"allow" toml:"allow"`
}

type ReadonlyConfig struct {
	Enabled bool   `json:"enabled" toml:"enabled"`
	Message string `json:"message" toml:"message"`
}

type MaintenanceConfig struct {
	Enabled bool   `json:"enabled" toml:"enabled"`
	Message string `json:"message" toml:"message"`
}

type RequireMFAConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type ForceOSHOnlyConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type TTYRecConfig struct {
	Enabled        bool `json:"enabled" toml:"enabled"`
	RetentionDays  int  `json:"retention_days" toml:"retention_days"` // 0 = keep forever
}

type SessionLimitsConfig struct {
	IdleTimeout          Duration `json:"idle_timeout" toml:"idle_timeout"`                                       // 0 = disabled
	MaxSessionDuration   Duration `json:"max_session_duration" toml:"max_session_duration"`                     // 0 = disabled
	MaxConcurrentSessions int     `json:"max_concurrent_sessions" toml:"max_concurrent_sessions"`              // 0 = unlimited
}

type SelfIngressConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type EgressKeyConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type TTYPlayConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type AliasSelfConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type AliasGroupConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type GroupsConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type RestrictedGrantsConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

// RestrictedCmds is the master kill-switch for the restricted-command feature
// (superset of RestrictedGrants): when disabled, restricted commands cannot run
// and their grant management commands are blocked.
type RestrictedCmdsConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type KnownHostsConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type SelfMFAConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type SelfPasswordConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type BackupCodesConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
}

type DenyRootTargetConfig struct {
	Enabled bool `json:"enabled" toml:"enabled"`
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
			Enabled:        true,
			DefaultPort:    22,
			HostKeyTTL:     Duration(24 * time.Hour),
			KeyscanTimeout: Duration(5 * time.Second),
		},
		MFA: MFAConfig{
			MaxAttempts: 3,
			BackoffBase: Duration(time.Second),
		},
		TOTP: TOTPConfig{
			BackupCodesCount: 10,
			BackupCodeLength: 8,
		},
		Proxy: ProxyConfig{
			TCPConnectTimeout: Duration(5 * time.Second),
			SFTPDialTimeout:   Duration(15 * time.Second),
			SFTPSSHTimeout:    Duration(15 * time.Second),
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

		// Feature toggles (defaults: on).
		SFTP:        SFTPConfig{Enabled: true},
		SCP:         SCPConfig{Enabled: true},
		RSync:       RSyncConfig{Enabled: true},
		Mosh:        MoshConfig{Enabled: true},
		Realms:      RealmsConfig{Enabled: true},
		PIV:         PIVConfig{Enabled: true},
		GuestAccess: GuestAccessConfig{Enabled: true},
		Interactive: InteractiveConfig{Allow: true},

		// Modes (defaults: off).
		Readonly:    ReadonlyConfig{Enabled: false, Message: "🔒 Read-only mode: modifications are disabled."},
		Maintenance: MaintenanceConfig{Enabled: false, Message: "🚧 Bastion under maintenance: only administrators may connect."},
		RequireMFA:  RequireMFAConfig{Enabled: false},
		ForceOSHOnly: ForceOSHOnlyConfig{Enabled: false},

		// Recording + session limits.
		TTYRec: TTYRecConfig{Enabled: true, RetentionDays: 30},
		Session: SessionLimitsConfig{
			IdleTimeout:           0,
			MaxSessionDuration:    0,
			MaxConcurrentSessions: 0,
		},

		// Self-service / admin sub-features (defaults: on).
		SelfIngress:      SelfIngressConfig{Enabled: true},
		EgressKey:        EgressKeyConfig{Enabled: true},
		TTYPlay:          TTYPlayConfig{Enabled: true},
		AliasSelf:        AliasSelfConfig{Enabled: true},
		AliasGroup:       AliasGroupConfig{Enabled: true},
		Groups:           GroupsConfig{Enabled: true},
		RestrictedGrants: RestrictedGrantsConfig{Enabled: true},
		RestrictedCmds:   RestrictedCmdsConfig{Enabled: true},
		KnownHosts:       KnownHostsConfig{Enabled: true},
		SelfMFA:          SelfMFAConfig{Enabled: true},
		SelfPassword:     SelfPasswordConfig{Enabled: true},
		BackupCodes:      BackupCodesConfig{Enabled: true},

		// Connection policy (default: off).
		DenyRootTarget: DenyRootTargetConfig{Enabled: false},
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

		// Note: db_driver here is the bootstrap default ("sqlite") — the real
		// backend is resolved later from env/db.conf in db.Init() and logged
		// as db_connect. We do not log db_driver to avoid implying the bastion
		// is running on SQLite.
		slog.Info("config_bootstrap_loaded",
			slog.String("instance_id", instanceID),
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

	// Normalize the database section in memory to the active backend. The
	// database section is not persisted (json:"-"), so this only keeps the
	// in-memory pool settings compatible (e.g. sqlite must stay single-connection).
	cfg.Database = normalizeDatabaseConfig(cfg.Database.Driver, cfg.Database)

	global.Store(cfg)
	models.SetRestrictedCmdsEnabled(cfg.RestrictedCmds.Enabled)
	slog.Info("config_loaded_from_db", slog.String("instance_id", boot.InstanceID))
	return nil
}

// normalizeDatabaseConfig adjusts the database section to be compatible with
// the active driver. Server backends (mysql/postgres) can use a connection
// pool, while sqlite must stay single-connection. When the stored section
// still carries the other engine's limits we reset them to the active
// driver's defaults.
func normalizeDatabaseConfig(driver string, db DatabaseConfig) DatabaseConfig {
	if driver == "sqlite" || driver == "" {
		if db.MaxOpenConns != 1 || db.MaxIdleConns != 1 {
			db.MaxOpenConns = 1
			db.MaxIdleConns = 1
		}
		return db
	}

	// Server backends: sqlite's single-connection limits are a leftover from a
	// previous backend and must be bumped back to the server defaults.
	if db.MaxOpenConns <= 1 || db.MaxIdleConns <= 1 {
		def := defaultConfig().Database
		db.MaxOpenConns = def.MaxOpenConns
		db.MaxIdleConns = def.MaxIdleConns
	}
	return db
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

	cfg.Database = normalizeDatabaseConfig(cfg.Database.Driver, cfg.Database)

	global.Store(cfg)
	models.SetRestrictedCmdsEnabled(cfg.RestrictedCmds.Enabled)
	slog.Debug("config_reloaded", slog.String("instance_id", boot.InstanceID))
}

// EnsureInstance creates the default config row for the instance if it doesn't exist.
func EnsureInstance(db *gorm.DB) error {
	boot := globalBoot.Load()
	if boot == nil {
		return fmt.Errorf("bootstrap not loaded")
	}

	cfg := defaultConfig()
	jsonData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal default config: %w", err)
	}

	// Use an explicit existence check + Create so the SQL is dialect-agnostic
	// (sqlite, mysql, postgres) and creation is logged exactly once. The
	// previous raw INSERT used datetime('now') and ON CONFLICT, which are
	// SQLite/Postgres-only and fail on MySQL.
	var inst models.BastionInstance
	err = db.Where("instance_id = ?", boot.InstanceID).First(&inst).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("ensure instance: %w", err)
		}
		inst = models.BastionInstance{
			InstanceID: boot.InstanceID,
			Role:       "master",
			Config:     string(jsonData),
		}
		if err := db.Create(&inst).Error; err != nil {
			return fmt.Errorf("ensure instance: %w", err)
		}
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
	return saveConfigLocked(db, cfg)
}

// saveConfigLocked persists the config without taking configMu. Callers must
// hold configMu (used by LoadFromDB/Reload which normalize while locked).
func saveConfigLocked(db *gorm.DB, cfg *Config) error {
	boot := globalBoot.Load()
	if boot == nil {
		return fmt.Errorf("bootstrap not loaded")
	}

	// Driver/DSN are bootstrap-only (json:"-") and not serialized.
	saveCfg := *cfg

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

// resolveInstanceID determines the instance identity from env, then the
// db.conf fallback file (written by entrypoint.sh), then hostname. The file
// fallback is required for ForceCommand children, which run as the connected
// user with the Docker INSTANCE_ID env var stripped by sshd.
func resolveInstanceID() string {
	if v := os.Getenv("INSTANCE_ID"); v != "" {
		return v
	}
	if v := readInstanceIDFromConf(); v != "" {
		return v
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "master"
}

// readInstanceIDFromConf reads INSTANCE_ID from the db.conf fallback file.
func readInstanceIDFromConf() string {
	f, err := os.Open(defaultConfig().Paths.DbConfFile)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if k, v, ok := strings.Cut(scanner.Text(), "="); ok && k == "INSTANCE_ID" {
			return v
		}
	}
	return ""
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

// DefaultLogFilePath returns the default log file path. It is safe to call
// before Load() (used to bootstrap the logger so early logs go to the file
// instead of the client console).
func DefaultLogFilePath() string {
	return defaultConfig().Paths.LogFile
}

// DefaultConfig returns a fresh default Config without triggering Load().
// Used by the logger setup, which must run before config is loaded.
func DefaultConfig() *Config {
	return defaultConfig()
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

	// Database and Paths are bootstrap/infra-only (json:"-") and are not
	// editable app config, so they are intentionally omitted from the TUI.

	// SSH
	add("ssh", "enabled", fmt.Sprintf("%t", cfg.SSH.Enabled), fmt.Sprintf("%t", def.SSH.Enabled))
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

	// Feature toggles
	add("sftp", "enabled", fmt.Sprintf("%t", cfg.SFTP.Enabled), fmt.Sprintf("%t", def.SFTP.Enabled))
	add("scp", "enabled", fmt.Sprintf("%t", cfg.SCP.Enabled), fmt.Sprintf("%t", def.SCP.Enabled))
	add("rsync", "enabled", fmt.Sprintf("%t", cfg.RSync.Enabled), fmt.Sprintf("%t", def.RSync.Enabled))
	add("mosh", "enabled", fmt.Sprintf("%t", cfg.Mosh.Enabled), fmt.Sprintf("%t", def.Mosh.Enabled))
	add("realms", "enabled", fmt.Sprintf("%t", cfg.Realms.Enabled), fmt.Sprintf("%t", def.Realms.Enabled))
	add("pivs", "enabled", fmt.Sprintf("%t", cfg.PIV.Enabled), fmt.Sprintf("%t", def.PIV.Enabled))
	add("guest_access", "enabled", fmt.Sprintf("%t", cfg.GuestAccess.Enabled), fmt.Sprintf("%t", def.GuestAccess.Enabled))
	add("interactive", "allow", fmt.Sprintf("%t", cfg.Interactive.Allow), fmt.Sprintf("%t", def.Interactive.Allow))

	// Modes
	add("readonly", "enabled", fmt.Sprintf("%t", cfg.Readonly.Enabled), fmt.Sprintf("%t", def.Readonly.Enabled))
	add("readonly", "message", cfg.Readonly.Message, def.Readonly.Message)
	add("maintenance", "enabled", fmt.Sprintf("%t", cfg.Maintenance.Enabled), fmt.Sprintf("%t", def.Maintenance.Enabled))
	add("maintenance", "message", cfg.Maintenance.Message, def.Maintenance.Message)
	add("require_mfa", "enabled", fmt.Sprintf("%t", cfg.RequireMFA.Enabled), fmt.Sprintf("%t", def.RequireMFA.Enabled))
	add("force_osh_only", "enabled", fmt.Sprintf("%t", cfg.ForceOSHOnly.Enabled), fmt.Sprintf("%t", def.ForceOSHOnly.Enabled))

	// Recording + session limits
	add("ttyrec", "enabled", fmt.Sprintf("%t", cfg.TTYRec.Enabled), fmt.Sprintf("%t", def.TTYRec.Enabled))
	add("ttyrec", "retention_days", fmt.Sprintf("%d", cfg.TTYRec.RetentionDays), fmt.Sprintf("%d", def.TTYRec.RetentionDays))
	add("session", "idle_timeout", cfg.Session.IdleTimeout.String(), def.Session.IdleTimeout.String())
	add("session", "max_session_duration", cfg.Session.MaxSessionDuration.String(), def.Session.MaxSessionDuration.String())
	add("session", "max_concurrent_sessions", fmt.Sprintf("%d", cfg.Session.MaxConcurrentSessions), fmt.Sprintf("%d", def.Session.MaxConcurrentSessions))

	// Self-service / admin sub-features
	add("self_ingress", "enabled", fmt.Sprintf("%t", cfg.SelfIngress.Enabled), fmt.Sprintf("%t", def.SelfIngress.Enabled))
	add("egress_key", "enabled", fmt.Sprintf("%t", cfg.EgressKey.Enabled), fmt.Sprintf("%t", def.EgressKey.Enabled))
	add("tty_play", "enabled", fmt.Sprintf("%t", cfg.TTYPlay.Enabled), fmt.Sprintf("%t", def.TTYPlay.Enabled))
	add("alias_self", "enabled", fmt.Sprintf("%t", cfg.AliasSelf.Enabled), fmt.Sprintf("%t", def.AliasSelf.Enabled))
	add("alias_group", "enabled", fmt.Sprintf("%t", cfg.AliasGroup.Enabled), fmt.Sprintf("%t", def.AliasGroup.Enabled))
	add("groups", "enabled", fmt.Sprintf("%t", cfg.Groups.Enabled), fmt.Sprintf("%t", def.Groups.Enabled))
	add("restricted_grants", "enabled", fmt.Sprintf("%t", cfg.RestrictedGrants.Enabled), fmt.Sprintf("%t", def.RestrictedGrants.Enabled))
	add("restricted_cmds", "enabled", fmt.Sprintf("%t", cfg.RestrictedCmds.Enabled), fmt.Sprintf("%t", def.RestrictedCmds.Enabled))
	add("known_hosts", "enabled", fmt.Sprintf("%t", cfg.KnownHosts.Enabled), fmt.Sprintf("%t", def.KnownHosts.Enabled))
	add("self_mfa", "enabled", fmt.Sprintf("%t", cfg.SelfMFA.Enabled), fmt.Sprintf("%t", def.SelfMFA.Enabled))
	add("self_password", "enabled", fmt.Sprintf("%t", cfg.SelfPassword.Enabled), fmt.Sprintf("%t", def.SelfPassword.Enabled))
	add("backup_codes", "enabled", fmt.Sprintf("%t", cfg.BackupCodes.Enabled), fmt.Sprintf("%t", def.BackupCodes.Enabled))

	// Connection policy
	add("deny_root_target", "enabled", fmt.Sprintf("%t", cfg.DenyRootTarget.Enabled), fmt.Sprintf("%t", def.DenyRootTarget.Enabled))

	return entries
}

// SetForTesting replaces the global config. Only for use in tests.
func SetForTesting(cfg *Config) {
	global.Store(cfg)
}

// idleResetFn is set by the session package so that long-running interactive
// commands (bastionConfig, etc.) can reset the idle watchdog while they hold
// the terminal.
var idleResetFn func()

// SetIdleResetFn registers the session idle-timer reset callback.
func SetIdleResetFn(fn func()) {
	idleResetFn = fn
}

// ResetIdleTimer resets the session idle watchdog. Safe to call from any
// interactive command handler that reads its own key loop.
func ResetIdleTimer() {
	if idleResetFn != nil {
		idleResetFn()
	}
}

// ResetForTesting clears the global config and sync.Once so the next call
// to Load() re-reads. Only for use in tests.
func ResetForTesting() {
	global.Store(nil)
	defaults = nil
	globalOnce = sync.Once{}
}
