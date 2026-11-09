package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"goBastion/internal/recording"
	"goBastion/internal/recording/archive"
)

var cliKeys struct {
	once    sync.Once
	rsa     [2]*rsa.PrivateKey
	signing ed25519.PrivateKey
	err     error
}

type cliFixture struct {
	directory, input, signer, verification, recipient, private, wrongPrivate string
	plaintext                                                                []byte
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newCLIFixture(t *testing.T) cliFixture {
	t.Helper()
	cliKeys.once.Do(func() {
		for i := range cliKeys.rsa {
			cliKeys.rsa[i], cliKeys.err = rsa.GenerateKey(rand.Reader, 3072)
			if cliKeys.err != nil {
				return
			}
		}
		_, cliKeys.signing, cliKeys.err = ed25519.GenerateKey(rand.Reader)
	})
	if cliKeys.err != nil {
		t.Fatal(cliKeys.err)
	}
	dir := privateTestDirectory(t)
	writePrivate := func(name string, key any) string {
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		path := filepath.Join(dir, name)
		data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
		defer clear(data)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	writePublic := func(name string, key any) string {
		encoded, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	fixture := cliFixture{directory: dir, input: filepath.Join(dir, "legacy.ttyrec"), plaintext: bytes.Repeat([]byte("legacy terminal content\x00\xff\n"), 10)}
	fixture.signer = writePrivate("signing.pem", cliKeys.signing)
	fixture.verification = writePublic("signing-public.pem", cliKeys.signing.Public())
	fixture.recipient = writePublic("recipient-public.pem", &cliKeys.rsa[0].PublicKey)
	fixture.private = writePrivate("recipient.pem", cliKeys.rsa[0])
	fixture.wrongPrivate = writePrivate("wrong-recipient.pem", cliKeys.rsa[1])
	if err := os.WriteFile(fixture.input, fixture.plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f cliFixture) sealArgs(output string) []string {
	return []string{"seal", "--input", f.input, "--output", output, "--signing-key", f.signer, "--recipient", f.recipient, "--session-id", "imported-session", "--bastion-id", "historical-bastion", "--protocol", "ssh", "--started-at", "2026-11-08T01:02:03Z", "--chunk-size", "32"}
}

func executeCLI(t *testing.T, args []string, want int) []byte {
	t.Helper()
	var out, diagnostics bytes.Buffer
	if got := execute(args, &out, &diagnostics); got != want {
		t.Fatalf("CLI returned %d, want %d (diagnostic %q)", got, want, diagnostics.String())
	}
	if want != 0 && out.Len() != 0 {
		t.Fatal("failed command released output on stdout")
	}
	return out.Bytes()
}

func assertNoStaging(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recording-admin-") {
			t.Fatal("operation retained output staging")
		}
	}
}

func TestRecordingAdminSealVerifyAndTransactionalDecrypt(t *testing.T) {
	f := newCLIFixture(t)
	encrypted := filepath.Join(f.directory, "recording.gobrec")
	manifestJSON := executeCLI(t, f.sealArgs(encrypted), 0)
	var manifest struct {
		Outcome archive.CaptureOutcome `json:"capture_outcome"`
		Context struct {
			Compression string `json:"compression"`
		} `json:"context"`
	}
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Outcome != archive.OutcomeImported || manifest.Context.Compression != "none" {
		t.Fatal("legacy import claimed capture completion or changed encoding")
	}
	encoded, err := os.ReadFile(encrypted)
	if err != nil || bytes.Contains(encoded, f.plaintext) {
		t.Fatal("sealed recording exposed plaintext")
	}
	verified := executeCLI(t, []string{"verify", "--input", encrypted, "--verify-key", f.verification}, 0)
	if !bytes.Equal(manifestJSON, verified) {
		t.Fatal("public-only verification changed manifest")
	}
	output := filepath.Join(f.directory, "replay.ttyrec")
	executeCLI(t, []string{"decrypt", "--input", encrypted, "--output", output, "--verify-key", f.verification, "--recipient-key", f.private}, 0)
	decoded, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(decoded, f.plaintext) {
		t.Fatal("decrypted recording was not preserved")
	}
	for _, path := range []string{encrypted, output} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("output was not private")
		}
	}
	assertNoStaging(t, f.directory)
}

func TestRecordingAdminRejectsBadArchivesWithoutOutput(t *testing.T) {
	f := newCLIFixture(t)
	encrypted := filepath.Join(f.directory, "recording.gobrec")
	executeCLI(t, f.sealArgs(encrypted), 0)
	encoded, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(encoded)
	corrupt[len(corrupt)-1] ^= 1
	for name, data := range map[string][]byte{"tampered": corrupt, "truncated": encoded[:len(encoded)-1]} {
		t.Run(name, func(t *testing.T) {
			input := filepath.Join(f.directory, name+".gobrec")
			output := filepath.Join(f.directory, name+".ttyrec")
			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			executeCLI(t, []string{"decrypt", "--input", input, "--output", output, "--verify-key", f.verification, "--recipient-key", f.private}, 1)
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("invalid archive published plaintext")
			}
			assertNoStaging(t, f.directory)
		})
	}
	output := filepath.Join(f.directory, "wrong-recipient.ttyrec")
	executeCLI(t, []string{"decrypt", "--input", encrypted, "--output", output, "--verify-key", f.verification, "--recipient-key", f.wrongPrivate}, 1)
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("wrong recipient published plaintext")
	}
	assertNoStaging(t, f.directory)
}

func TestRecordingAdminNeverOverwritesFilesOrSymlinks(t *testing.T) {
	f := newCLIFixture(t)
	protected := filepath.Join(f.directory, "protected")
	want := []byte("existing file stays unchanged")
	if err := os.WriteFile(protected, want, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(f.directory, "symlink")
	if err := os.Symlink(protected, symlink); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{protected, symlink} {
		executeCLI(t, f.sealArgs(output), 1)
	}
	got, err := os.ReadFile(protected)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("existing output was modified")
	}
	assertNoStaging(t, f.directory)
}

func TestRecordingAdminRejectsUnsafeConfigurationAndQuota(t *testing.T) {
	f := newCLIFixture(t)
	output := filepath.Join(f.directory, "must-not-exist.gobrec")
	for _, extra := range [][]string{{"--max-input-bytes", "8"}, {"--max-input-bytes", "0"}, {"--compression", "unknown"}, {"--chunk-size", strconv.Itoa(archive.MaxChunkSize + 1)}} {
		want := 1
		if extra[0] == "--max-input-bytes" && extra[1] == "0" {
			want = 2
		}
		executeCLI(t, append(f.sealArgs(output), extra...), want)
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("invalid configuration published output")
		}
	}
	if err := os.Chmod(f.signer, 0644); err != nil {
		t.Fatal(err)
	}
	executeCLI(t, f.sealArgs(output), 1)
	if err := os.Chmod(f.signer, 0600); err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(f.directory, "shared")
	if err := os.Mkdir(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	executeCLI(t, f.sealArgs(filepath.Join(unsafe, "output")), 1)
	args := f.sealArgs("-")
	executeCLI(t, args, 2)
	assertNoStaging(t, f.directory)
}

func TestRecordingAdminFailedTransactionalWriteLeavesNoOutput(t *testing.T) {
	path := filepath.Join(privateTestDirectory(t), "output")
	_, err := atomicOutput(path, func(dst *os.File) (archive.Manifest, error) {
		if _, err := dst.Write([]byte("authenticated prefix must be discarded")); err != nil {
			t.Fatal(err)
		}
		return archive.Manifest{}, io.ErrUnexpectedEOF
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		info, _ := os.Stat(filepath.Dir(path))
		t.Fatalf("transaction did not preserve write failure: %v (directory mode %o owner %T effective UID %d)", err, info.Mode().Perm(), info.Sys(), os.Geteuid())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed transaction published output")
	}
	assertNoStaging(t, filepath.Dir(path))
}

func TestRecordingAdminRequiresRootAndRefusesSSH(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		if got := run([]string{"verify", "--help"}, &out, &diagnostics); got != 2 {
			t.Fatal("non-root CLI accepted administrative operation")
		}
		return
	}
	t.Setenv("SSH_CONNECTION", "")
	if got := run([]string{"verify", "--help"}, &out, &diagnostics); got != 2 {
		t.Fatal("SSH CLI accepted administrative operation")
	}
}

func TestRecordingAdminActualRootConsoleRoundTrip(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Skip("requires actual root in the disposable test container")
	}
	for _, name := range []string{"SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	f := newCLIFixture(t)
	sealed := filepath.Join(f.directory, "root.gobrec")
	var out, diagnostics bytes.Buffer
	if code := run(f.sealArgs(sealed), &out, &diagnostics); code != 0 {
		t.Fatalf("root console seal failed: %s", diagnostics.String())
	}
	if code := run([]string{"verify", "--input", sealed, "--verify-key", f.verification}, io.Discard, &diagnostics); code != 0 {
		t.Fatal("public-only root verification failed")
	}
	decrypted := filepath.Join(f.directory, "root.ttyrec")
	if code := run([]string{"decrypt", "--input", sealed, "--output", decrypted, "--verify-key", f.verification, "--recipient-key", f.private}, io.Discard, &diagnostics); code != 0 {
		t.Fatal("root console decrypt failed")
	}
	data, err := os.ReadFile(decrypted)
	if err != nil || !bytes.Equal(data, f.plaintext) {
		t.Fatal("root round-trip content mismatch")
	}
}

func TestRecordingAdminAuditsAccessWithoutContentOrKeyPaths(t *testing.T) {
	f := newCLIFixture(t)
	var audit, out, diagnostics bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&audit, nil))
	if code := executeWithAudit(f.sealArgs(filepath.Join(f.directory, "audited.gobrec")), &out, &diagnostics, log); code != 0 {
		t.Fatalf("audited seal failed: %s", diagnostics.String())
	}
	if !strings.Contains(audit.String(), "recording_admin_access") || !strings.Contains(audit.String(), "recording_admin_result") || !strings.Contains(audit.String(), `"decision":"allow"`) || !strings.Contains(audit.String(), `"archive_id":`) {
		t.Fatal("administrative recording access was not audited")
	}
	if bytes.Contains(audit.Bytes(), f.plaintext) || strings.Contains(audit.String(), f.signer) || strings.Contains(audit.String(), f.input) {
		t.Fatal("recording audit exposed content or protected paths")
	}
}

func TestRecordingAdminRejectsMutablePublicTrustFiles(t *testing.T) {
	f := newCLIFixture(t)
	if err := os.Chmod(f.verification, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readVerificationKeys([]string{f.verification}); err == nil {
		t.Fatal("writable trust key accepted")
	}
	if err := os.Chmod(f.verification, 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.directory, "trust-link.pem")
	if err := os.Symlink(f.verification, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readVerificationKeys([]string{link}); err == nil {
		t.Fatal("symlink trust key accepted")
	}
}

func TestConcurrentRecordingPublishersNeverOverwriteWinner(t *testing.T) {
	f := newCLIFixture(t)
	output := filepath.Join(f.directory, "race.gobrec")
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := sealFile(f.input, output, f.signer, []string{f.recipient}, defaultInputLimit, archive.Provenance{SessionID: "concurrent-import", BastionID: "fixture", Protocol: "ssh", StartedAt: time.Now().UTC()}, archive.Options{})
			results <- err
		}()
	}
	success := 0
	for range 2 {
		if <-results == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful publishers=%d, want1", success)
	}
	trusted, err := readVerificationKeys([]string{f.verification})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFile(output, defaultInputLimit, trusted); err != nil {
		t.Fatal("published winner invalid")
	}
	assertNoStaging(t, f.directory)
}

func TestRecordingAdminRejectsLeadingPEMJunkAndPrivateSymlinks(t *testing.T) {
	f := newCLIFixture(t)
	for _, path := range []string{f.signer, f.verification} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		junk := filepath.Join(f.directory, filepath.Base(path)+".junk")
		if err := os.WriteFile(junk, append([]byte("unrecognized prefix\n"), data...), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readKeyPEM(junk, path == f.signer); err == nil {
			t.Fatal("key parser skipped leading junk")
		}
		bundle := filepath.Join(f.directory, filepath.Base(path)+".bundle")
		if err := os.WriteFile(bundle, append(bytes.Clone(data), data...), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readKeyPEM(bundle, path == f.signer); err == nil {
			t.Fatal("key parser accepted multiple PEM blocks")
		}
		for i, prefix := range []string{"-----BEGIN JUNK-----\n!invalid base64!\n-----END JUNK-----\n", "-----BEGIN JUNK-----\n"} {
			malformed := filepath.Join(f.directory, filepath.Base(path)+".malformed-"+strconv.Itoa(i))
			if err := os.WriteFile(malformed, append([]byte(prefix), data...), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readKeyPEM(malformed, path == f.signer); err == nil {
				t.Fatal("key parser skipped malformed initial PEM")
			}
		}
	}
	link := filepath.Join(f.directory, "signer-link.pem")
	if err := os.Symlink(f.signer, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyPEM(link, true); err == nil {
		t.Fatal("private key leaf symlink was followed")
	}
}

func TestVerifyPublishedRecording(t *testing.T) {
	archive := t.TempDir()
	if err := os.Chmod(archive, 0700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src.gz")
	content := []byte("recording-bytes")
	if err := os.WriteFile(src, content, 0600); err != nil {
		t.Fatal(err)
	}
	rel := "account/server/session.ttyrec.gz"
	if err := recording.Publish(archive, src, rel, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(archive, rel)
	out := executeCLI(t, []string{"verify-published", "--input", path}, 0)
	if !bytes.Contains(out, []byte(`"status":"ok"`)) {
		t.Fatalf("unexpected output: %s", out)
	}
	_ = executeCLI(t, []string{"verify-published", "--input", path, "--max-input-bytes", "1"}, 1)
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = executeCLI(t, []string{"verify-published", "--input", path}, 1)
}
