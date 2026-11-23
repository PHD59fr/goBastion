package recording

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"goBastion/internal/recording/archive"
)

func TestLiveFileRejectsInvalidOwnerBeforeTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "keys"), 0700); err != nil {
		t.Fatal(err)
	}
	want := []byte("fixture key material")
	if err := os.WriteFile(filepath.Join(dir, "keys", "key"), want, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	data, err := readLiveFile(root, "/keys/key", os.Geteuid(), true)
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("valid owner: data=%q, error=%v", data, err)
	}

	owners := []int{-1}
	if strconv.IntSize == 64 {
		overflow := uint64(1) << 32
		owners = append(owners, int(overflow), int(overflow+uint64(os.Geteuid())))
	}
	for _, owner := range owners {
		t.Run(strconv.Itoa(owner), func(t *testing.T) {
			for _, path := range []string{"/keys/key", "/missing/key"} {
				data, err := readLiveFile(root, path, owner, true)
				if err == nil || err.Error() != "invalid recording key owner" || data != nil {
					t.Fatalf("owner %d at %s must fail before traversal: data=%q, error=%v", owner, path, data, err)
				}
			}
		})
	}
}

func TestCheckedUnixOwnerIDBounds(t *testing.T) {
	if id, err := checkedUnixOwnerID(0); err != nil || id != 0 {
		t.Fatalf("root owner: %d, %v", id, err)
	}
	if strconv.IntSize == 64 {
		maximum := uint64(1)<<32 - 1
		if id, err := checkedUnixOwnerID(int(maximum)); err != nil || uint64(id) != maximum {
			t.Fatalf("maximum owner: %d, %v", id, err)
		}
	}
}

var liveFixtureKeys struct {
	sync.Once
	recipient *rsa.PrivateKey
	signer    ed25519.PrivateKey
	err       error
}

func liveKeys(t *testing.T) (*rsa.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	liveFixtureKeys.Do(func() {
		liveFixtureKeys.recipient, liveFixtureKeys.err = rsa.GenerateKey(rand.Reader, 3072)
		if liveFixtureKeys.err == nil {
			_, liveFixtureKeys.signer, liveFixtureKeys.err = ed25519.GenerateKey(rand.Reader)
		}
	})
	if liveFixtureKeys.err != nil {
		t.Fatal(liveFixtureKeys.err)
	}
	return liveFixtureKeys.recipient, liveFixtureKeys.signer
}

func liveFixture(t *testing.T) (*os.File, string) {
	t.Helper()
	recipient, signer := liveKeys(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	signingDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	recipientDER, err := x509.MarshalPKIXPublicKey(&recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"sign.pem":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signingDER}),
		"recipient.pem": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: recipientDER}),
	}
	cfg, err := json.Marshal(livePolicyConfig{Version: 1, SigningKey: "/sign.pem", Recipients: []string{"/recipient.pem"}, ChunkSize: 128})
	if err != nil {
		t.Fatal(err)
	}
	files["policy.json"] = cfg
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readLiveFile(root, "/policy.json", os.Geteuid(), false); err != nil {
		t.Fatalf("fixture guard: %v", err)
	}
	return root, dir
}

func TestLivePolicyAbsentAndFailClosed(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		root, _ := liveFixture(t)
		policy, err := loadLivePolicy(root, "/missing.json", os.Geteuid(), false)
		if err != nil || policy != nil {
			t.Fatalf("absent policy: %v, %v", policy, err)
		}
	})
	for _, name := range []string{"unprivileged", "malformed", "unknown-field", "symlink", "ancestor-symlink", "unavailable", "writable-policy", "writable-key", "missing-key", "wrong-owner", "duplicate-recipient"} {
		t.Run(name, func(t *testing.T) {
			root, dir := liveFixture(t)
			privileged := true
			owner := os.Geteuid()
			path := "/policy.json"
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "unprivileged":
				privileged = false
			case "malformed":
				must(os.WriteFile(filepath.Join(dir, "policy.json"), []byte("{"), 0600))
			case "unknown-field":
				must(os.WriteFile(filepath.Join(dir, "policy.json"), []byte(`{"version":1,"signing_key":"/sign.pem","recipients":["/recipient.pem"],"extra":true}`), 0600))
			case "symlink":
				must(os.Symlink("policy.json", filepath.Join(dir, "link")))
				path = "/link"
			case "ancestor-symlink":
				must(os.Symlink(".", filepath.Join(dir, "link")))
				path = "/link/policy.json"
			case "unavailable":
				path = "/sign.pem/policy.json"
			case "writable-policy":
				must(os.Chmod(filepath.Join(dir, "policy.json"), 0660))
			case "writable-key":
				must(os.Chmod(filepath.Join(dir, "sign.pem"), 0644))
			case "missing-key":
				must(os.Rename(filepath.Join(dir, "sign.pem"), filepath.Join(dir, "hidden.pem")))
			case "wrong-owner":
				owner++
			case "duplicate-recipient":
				cfg, err := json.Marshal(livePolicyConfig{Version: 1, SigningKey: "/sign.pem", Recipients: []string{"/recipient.pem", "/recipient.pem"}})
				must(err)
				must(os.WriteFile(filepath.Join(dir, "policy.json"), cfg, 0600))
			}
			policy, err := loadLivePolicy(root, path, owner, privileged)
			if policy != nil {
				policy.Close()
				t.Fatal("unsafe policy loaded")
			}
			if err == nil {
				t.Fatal("unsafe or present policy enabled plaintext fallback")
			}
		})
	}
}

func TestLiveCaptureRoundTripAndRecorderOutcome(t *testing.T) {
	recipient, signer := liveKeys(t)
	payload := bytes.Repeat([]byte("recorded ttyrec bytes\x00"), 100)
	for _, fixture := range []struct {
		name                   string
		commandErr, contextErr error
		outcome                archive.CaptureOutcome
	}{
		{"success", nil, nil, archive.OutcomeComplete},
		{"recorder-failed", errors.New("exit status 1"), nil, archive.OutcomeInterruptedPrefix},
		{"cancelled", nil, context.Canceled, archive.OutcomeInterruptedPrefix},
		{"deadline", errors.New("signal: killed"), context.DeadlineExceeded, archive.OutcomeInterruptedPrefix},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root, _ := liveFixture(t)
			policy, err := loadLivePolicy(root, "/policy.json", os.Geteuid(), true)
			if err != nil {
				t.Fatal(err)
			}
			defer policy.Close()
			var dst bytes.Buffer
			writer, err := NewCaptureWriter(&dst, policy, archive.Provenance{SessionID: "session", BastionID: "bastion", Account: "alice", Protocol: "postgresql", StartedAt: time.Now().UTC()})
			if err != nil {
				t.Fatal(err)
			}
			// Multiple live flushes produce intermediate short encrypted frames.
			// They must remain verifiable after later writes and finalization.
			for _, block := range [][]byte{payload[:1], payload[1:100], payload[100:]} {
				if _, err := writer.Write(block); err != nil {
					t.Fatal(err)
				}
				if err := writer.Flush(); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.CloseAfterRecorder(fixture.commandErr, fixture.contextErr); err != nil {
				t.Fatal(err)
			}
			writer.Abort() // Successful finalization must survive deferred cleanup.
			if bytes.Contains(dst.Bytes(), []byte("recorded ttyrec bytes")) {
				t.Fatal("plaintext in encrypted output")
			}
			var compressed bytes.Buffer
			manifest, err := archive.Decrypt(bytes.NewReader(dst.Bytes()), int64(dst.Len()), &compressed, []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}, []*rsa.PrivateKey{recipient})
			if err != nil {
				t.Fatal(err)
			}
			if manifest.CaptureOutcome() != fixture.outcome {
				t.Fatalf("outcome %q, want %q", manifest.CaptureOutcome(), fixture.outcome)
			}
			reader, err := gzip.NewReader(&compressed)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("decrypted capture differs")
			}
		})
	}
}

func TestLiveCapturePlaintextWithoutPolicy(t *testing.T) {
	var dst bytes.Buffer
	writer, err := NewCaptureWriter(&dst, nil, archive.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("legacy ttyrec")); err != nil {
		t.Fatal(err)
	}
	if err := writer.CloseAfterRecorder(nil, nil); err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(&dst)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "legacy ttyrec" {
		t.Fatalf("capture = %q, %v", got, err)
	}
}

type failingLiveSink struct {
	bytes.Buffer
	fail bool
}

func (s *failingLiveSink) Write(p []byte) (int, error) {
	if s.fail {
		return 0, io.ErrClosedPipe
	}
	return s.Buffer.Write(p)
}

func TestLiveCaptureWriteFailureCannotFinalize(t *testing.T) {
	root, _ := liveFixture(t)
	policy, err := loadLivePolicy(root, "/policy.json", os.Geteuid(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	sink := &failingLiveSink{}
	writer, err := NewCaptureWriter(sink, policy, archive.Provenance{SessionID: "session", BastionID: "bastion", Protocol: "postgresql", StartedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("captured prefix")); err != nil {
		t.Fatal(err)
	}
	sink.fail = true
	if err := writer.Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("flush = %v", err)
	}
	sink.fail = false
	if err := writer.CloseAfterRecorder(nil, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("finalization forgot failure: %v", err)
	}
	writer.Abort()
	_, signer := liveKeys(t)
	if _, err := archive.Verify(bytes.NewReader(sink.Bytes()), []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}); err == nil {
		t.Fatal("failed capture has valid signed manifest")
	}
}

func TestLivePolicyConcurrentLoadsOwnSigningMaterial(t *testing.T) {
	root, _ := liveFixture(t)
	const workers = 8
	results := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			policy, err := loadLivePolicy(root, "/policy.json", os.Geteuid(), true)
			if err != nil {
				results <- err
				return
			}
			// Every load owns a separate private-key allocation. Closing one loader
			// must not zero another recorder's signing key.
			defer policy.Close()
			if !bytes.Equal(ed25519.NewKeyFromSeed(policy.signer[:ed25519.SeedSize]), policy.signer) {
				results <- errors.New("concurrent policy load lost signing material")
			}
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		t.Error(err)
	}
}
