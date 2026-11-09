package recording

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVerifyPublishedIntegrityDetectsTampering(t *testing.T) {
	archive := t.TempDir()
	_ = os.Chmod(archive, 0700)
	src := filepath.Join(t.TempDir(), "src.ttyrec.gz")
	if err := os.WriteFile(src, []byte("recording-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	rel := "account/server/session.ttyrec.gz"
	if err := Publish(archive, src, rel, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(archive, rel)
	if err := VerifyPublishedIntegrity(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublishedIntegrity(path); err == nil {
		t.Fatal("expected integrity mismatch")
	}
}

func integrityFixture(t *testing.T) (string, publishIntegrityManifest) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.ttyrec.gz")
	data := []byte("recording-bytes")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	manifest := publishIntegrityManifest{Version: 1, Algorithm: "sha256", Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}
	writeIntegrityFixture(t, path, manifest)
	return path, manifest
}

func writeIntegrityFixture(t *testing.T, path string, manifest publishIntegrityManifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".integrity.json", data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPublishedIntegrityRejectsInvalidManifest(t *testing.T) {
	for _, name := range []string{"missing version", "future version", "algorithm", "negative size", "wrong size", "short hash", "uppercase hash", "invalid hash"} {
		t.Run(name, func(t *testing.T) {
			path, manifest := integrityFixture(t)
			switch name {
			case "missing version":
				manifest.Version = 0
			case "future version":
				manifest.Version = 2
			case "algorithm":
				manifest.Algorithm = "sha512"
			case "negative size":
				manifest.Size = -1
			case "wrong size":
				manifest.Size++
			case "short hash":
				manifest.SHA256 = manifest.SHA256[:62]
			case "uppercase hash":
				manifest.SHA256 = strings.ToUpper(manifest.SHA256)
			case "invalid hash":
				manifest.SHA256 = strings.Repeat("z", 64)
			}
			writeIntegrityFixture(t, path, manifest)
			if err := VerifyPublishedIntegrity(path); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestVerifyPublishedIntegrityBoundsReads(t *testing.T) {
	path, manifest := integrityFixture(t)
	if err := VerifyPublishedIntegrityWithLimit(path, manifest.Size); err != nil {
		t.Fatal("exact limit rejected:", err)
	}
	for _, limit := range []int64{-1, 0, manifest.Size - 1, 1<<63 - 1} {
		if err := VerifyPublishedIntegrityWithLimit(path, limit); err == nil {
			t.Fatalf("accepted limit %d", limit)
		}
	}
	if err := os.WriteFile(path+".integrity.json", []byte(strings.Repeat(" ", int(integrityManifestLimit)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublishedIntegrity(path); err == nil {
		t.Fatal("oversized sidecar accepted")
	}
}

func TestVerifyPublishedIntegrityRejectsUnsafeFiles(t *testing.T) {
	for _, target := range []string{"recording", "manifest"} {
		for _, kind := range []string{"symlink", "fifo", "directory", "missing"} {
			t.Run(target+"/"+kind, func(t *testing.T) {
				path, _ := integrityFixture(t)
				victim := path
				if target == "manifest" {
					victim += ".integrity.json"
				}
				original := victim + ".original"
				if err := os.Rename(victim, original); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "symlink":
					err = os.Symlink(original, victim)
				case "fifo":
					err = unix.Mkfifo(victim, 0600)
				case "directory":
					err = os.Mkdir(victim, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyPublishedIntegrity(path); err == nil {
					t.Fatal("unsafe input accepted")
				}
			})
		}
	}
}
