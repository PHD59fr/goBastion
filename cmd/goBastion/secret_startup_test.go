package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"goBastion/internal/config"
)

func TestStartupRejectsMissingOrInvalidEncryptionBeforeOpeningDB(t *testing.T) {
	if os.Getenv("GOB_STARTUP_KEY_HELPER") == "1" {
		cfg := config.DefaultConfig()
		cfg.Paths.LogFile = filepath.Join(os.Getenv("GOB_STARTUP_TEST_DIR"), "startup.log")
		config.SetForTesting(cfg)
		main()
		os.Exit(99)
	}
	for name, key := range map[string]string{
		"missing": "", "malformed": "NOT-A-SECRET-INVALID-BASE64",
		"raw passphrase": strings.Repeat("x", 32),
		"AES128 active":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			databasePath := filepath.Join(dir, "must-not-exist.db")
			cmd := exec.Command(os.Args[0], "-test.run=^TestStartupRejectsMissingOrInvalidEncryptionBeforeOpeningDB$")
			for _, entry := range os.Environ() {
				if strings.HasPrefix(entry, "EGRESS_ENC_") || strings.HasPrefix(entry, "OTEL_") || strings.HasPrefix(entry, "DB_DSN=") || strings.HasPrefix(entry, "DB_DRIVER=") {
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "GOB_STARTUP_KEY_HELPER=1", "GOB_STARTUP_TEST_DIR="+dir, "EGRESS_ENC_KEY="+key, "DB_DRIVER=sqlite", "DB_DSN="+databasePath)
			output, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				t.Fatalf("startup did not fail closed: %v", err)
			}
			if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
				t.Fatal("invalid key caused a database write")
			}
			logs, _ := os.ReadFile(filepath.Join(dir, "startup.log"))
			logs = append(logs, output...)
			if !bytes.Contains(logs, []byte("persistent_secret_configuration_invalid")) {
				t.Fatal("startup failed for an unrelated reason")
			}
			if key != "" && bytes.Contains(logs, []byte(key)) {
				t.Fatal("encryption key entered logs")
			}
		})
	}
}
