package config

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.Paths.HomeBaseDir != "/home" {
		t.Errorf("HomeBaseDir = %q, want /home", cfg.Paths.HomeBaseDir)
	}
	if cfg.Paths.TtyrecDir != "/app/ttyrec" {
		t.Errorf("TtyrecDir = %q, want /app/ttyrec", cfg.Paths.TtyrecDir)
	}
	if cfg.Paths.LogFile != "/goBastion.log" {
		t.Errorf("LogFile = %q, want /goBastion.log", cfg.Paths.LogFile)
	}
	if cfg.Paths.DbDir != "/var/lib/goBastion" {
		t.Errorf("DbDir = %q, want /var/lib/goBastion", cfg.Paths.DbDir)
	}
	if cfg.SSH.DefaultPort != 22 {
		t.Errorf("DefaultPort = %d, want 22", cfg.SSH.DefaultPort)
	}
	if cfg.SSH.HostKeyTTL != 24*time.Hour {
		t.Errorf("HostKeyTTL = %v, want 24h", cfg.SSH.HostKeyTTL)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("Driver = %q, want sqlite", cfg.Database.Driver)
	}
	if cfg.Database.ConnMaxLifetime != 5*time.Minute {
		t.Errorf("ConnMaxLifetime = %v, want 5m", cfg.Database.ConnMaxLifetime)
	}
	if cfg.Database.SQLite.CacheSize != 2000 {
		t.Errorf("CacheSize = %d, want 2000", cfg.Database.SQLite.CacheSize)
	}
	if cfg.MFA.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", cfg.MFA.MaxAttempts)
	}
	if cfg.Proxy.TCPConnectTimeout != 5*time.Second {
		t.Errorf("TCPConnectTimeout = %v, want 5s", cfg.Proxy.TCPConnectTimeout)
	}
	if cfg.Proxy.SFTPDialTimeout != 15*time.Second {
		t.Errorf("SFTPDialTimeout = %v, want 15s", cfg.Proxy.SFTPDialTimeout)
	}
	if cfg.Sync.IntervalSeconds != 300 {
		t.Errorf("IntervalSeconds = %d, want 300", cfg.Sync.IntervalSeconds)
	}
	if cfg.Security.DefaultWildcardUsername != "root" {
		t.Errorf("DefaultWildcardUsername = %q, want root", cfg.Security.DefaultWildcardUsername)
	}
	if cfg.Account.MaxInactiveDays != 0 {
		t.Errorf("MaxInactiveDays = %d, want 0", cfg.Account.MaxInactiveDays)
	}
}

func TestEnvOverrides(t *testing.T) {
	ResetForTesting()
	t.Setenv("DB_DRIVER", "mysql")
	t.Setenv("DB_DSN", "user:pass@tcp(host:3306)/db")
	defer func() { _ = os.Unsetenv("DB_DRIVER") }()
	defer func() { _ = os.Unsetenv("DB_DSN") }()

	cfg := Load()

	if cfg.Database.Driver != "mysql" {
		t.Errorf("Driver = %q, want mysql (env override)", cfg.Database.Driver)
	}
	if cfg.Database.DSN != "user:pass@tcp(host:3306)/db" {
		t.Errorf("DSN = %q, want user:pass@tcp(host:3306)/db (env override)", cfg.Database.DSN)
	}
}

func TestSQLitePoolDefaults(t *testing.T) {
	ResetForTesting()
	_ = os.Unsetenv("DB_DRIVER")
	_ = os.Unsetenv("DB_DSN")
	cfg := Load()

	if cfg.Database.MaxOpenConns != 1 {
		t.Errorf("SQLite MaxOpenConns = %d, want 1", cfg.Database.MaxOpenConns)
	}
	if cfg.Database.MaxIdleConns != 1 {
		t.Errorf("SQLite MaxIdleConns = %d, want 1", cfg.Database.MaxIdleConns)
	}
}

func TestInstanceIDResolution(t *testing.T) {
	ResetForTesting()
	_ = os.Unsetenv("INSTANCE_ID")

	Load()
	id := InstanceID()
	if id == "" {
		t.Error("InstanceID() should not be empty")
	}

	ResetForTesting()
	t.Setenv("INSTANCE_ID", "my-custom-instance")
	Load()
	id = InstanceID()
	if id != "my-custom-instance" {
		t.Errorf("InstanceID() = %q, want my-custom-instance", id)
	}
}

func TestConfigDiff(t *testing.T) {
	ResetForTesting()
	_ = os.Unsetenv("DB_DRIVER")
	_ = os.Unsetenv("DB_DSN")
	Load()

	entries := ConfigDiff()
	if len(entries) == 0 {
		t.Fatal("ConfigDiff() returned empty")
	}

	// With defaults, nothing should be modified.
	for _, e := range entries {
		if e.Modified {
			t.Errorf("entry %s.%s is modified but should match default", e.Section, e.Key)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	cfg := defaultConfig()
	cfg.Account.MaxInactiveDays = 30
	cfg.SSH.DefaultPort = 2222
	cfg.MFA.MaxAttempts = 5

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored := defaultConfig()
	if err := json.Unmarshal(data, restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if restored.Account.MaxInactiveDays != 30 {
		t.Errorf("MaxInactiveDays = %d, want 30", restored.Account.MaxInactiveDays)
	}
	if restored.SSH.DefaultPort != 2222 {
		t.Errorf("DefaultPort = %d, want 2222", restored.SSH.DefaultPort)
	}
	if restored.MFA.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d, want 5", restored.MFA.MaxAttempts)
	}
}

func TestGetDefaults(t *testing.T) {
	ResetForTesting()
	_ = os.Unsetenv("DB_DRIVER")
	_ = os.Unsetenv("DB_DSN")
	Load()

	def := GetDefaults()
	if def == nil {
		t.Fatal("GetDefaults() returned nil")
	}
	if def.Paths.HomeBaseDir != "/home" {
		t.Errorf("defaults HomeBaseDir = %q, want /home", def.Paths.HomeBaseDir)
	}
}
