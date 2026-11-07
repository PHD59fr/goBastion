package tty

import (
	"fmt"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"os"
	"path/filepath"
	"testing"
)

func TestRegressionPlaybackPropagatesDecompressionError(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) { testPlaybackResult(t, failed) })
	}
}
func testPlaybackResult(t *testing.T, failed bool) {
	config.ResetForTesting()
	_ = config.Load()
	defer config.ResetForTesting()
	cfg := config.DefaultConfig()
	cfg.Paths.TtyrecDir = t.TempDir()
	config.SetForTesting(cfg)
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	name := "deploy.fixture:22_2026-11-07_00-00-00.ttyrec.gz"
	dir := filepath.Join(cfg.Paths.TtyrecDir, "alice", "fixture")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	decompressor := "#!/bin/sh\nprintf data\nexit 0\n"
	if failed {
		decompressor = "#!/bin/sh\nprintf partial\nexit 1\n"
	}
	for name, script := range map[string]string{"zcat": decompressor, "ttyplay": "#!/bin/sh\ncat >/dev/null\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := Play(nil, &user, []string{"--file", name}); (err != nil) != failed {
		t.Fatal("ttyPlay reported success although decompression failed")
	}
}
