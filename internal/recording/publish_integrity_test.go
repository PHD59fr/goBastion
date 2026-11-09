package recording

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPublishWritesIntegrityManifest(t *testing.T) {
	archive := t.TempDir()
	if err := os.Chmod(archive, 0700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src.ttyrec.gz")
	content := []byte("recording-bytes")
	if err := os.WriteFile(src, content, 0600); err != nil {
		t.Fatal(err)
	}
	rel := "account/server/session.ttyrec.gz"
	if err := Publish(archive, src, rel, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(archive, rel))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("published content mismatch: %q", got)
	}
	mf, err := os.ReadFile(filepath.Join(archive, rel+".integrity.json"))
	if err != nil {
		t.Fatalf("integrity manifest missing: %v", err)
	}
	var m publishIntegrityManifest
	if err := json.Unmarshal(mf, &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if m.Algorithm != "sha256" || m.SHA256 != hex.EncodeToString(sum[:]) || m.Size != int64(len(content)) || m.RelativePath != rel {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	recordingInfo, err := os.Stat(filepath.Join(archive, rel))
	if err != nil {
		t.Fatal(err)
	}
	manifestInfo, err := os.Stat(filepath.Join(archive, rel+".integrity.json"))
	if err != nil {
		t.Fatal(err)
	}
	recordingStat := recordingInfo.Sys().(*syscall.Stat_t)
	manifestStat := manifestInfo.Sys().(*syscall.Stat_t)
	if manifestInfo.Mode().Perm() != 0640 || manifestStat.Uid != recordingStat.Uid || manifestStat.Gid != recordingStat.Gid {
		t.Fatalf("manifest permissions differ from recording: %v uid=%d gid=%d", manifestInfo.Mode(), manifestStat.Uid, manifestStat.Gid)
	}
}

func TestPublishPreservesExistingSidecar(t *testing.T) {
	archive := privateTestArchive(t)
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("recording"), 0600); err != nil {
		t.Fatal(err)
	}
	relative := "account/server/session.ttyrec.gz"
	parent := filepath.Join(archive, filepath.Dir(relative))
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(archive, relative+".integrity.json")
	if err := os.WriteFile(sidecar, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Publish(archive, source, relative, os.Geteuid()); err != nil {
		t.Fatal("sidecar collision prevented primary publication:", err)
	}
	if got, err := os.ReadFile(sidecar); err != nil || string(got) != "existing" {
		t.Fatalf("existing sidecar replaced: %q %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(archive, relative)); err != nil || string(got) != "recording" {
		t.Fatalf("primary recording missing: %q %v", got, err)
	}
	if entries, err := filepath.Glob(filepath.Join(parent, ".publish-*")); err != nil || len(entries) != 0 {
		t.Fatalf("publication staging remains: %v %v", entries, err)
	}
}
