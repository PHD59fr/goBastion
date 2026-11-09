// recording-admin seals legacy input and verifies/decrypts recording archives.
// It is an offline root administrative tool, not a live capture service.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"goBastion/internal/recording"
	"goBastion/internal/recording/archive"
	"goBastion/internal/telemetry"
	"goBastion/internal/utils/logger"
)

const defaultInputLimit int64 = 1 << 30
const maximumInputLimit int64 = (1 << 40) + (1 << 27)
const keyFileLimit = 64 << 10

type fileFlags []string

func (f *fileFlags) String() string { return strings.Join(*f, ",") }
func (f *fileFlags) Set(value string) error {
	if value == "" || len(*f) >= archive.MaxRecipients {
		return errors.New("invalid number of key files")
	}
	*f = append(*f, value)
	return nil
}

func main() {
	audit := logger.NewLogger()
	if _, err := telemetry.ConfigureFromEnv(audit); err != nil {
		audit.Error("tracing_configuration_invalid")
		os.Exit(1)
	}
	logger.SetTraceResolver(telemetry.TraceIDs)
	code := runWithAudit(os.Args[1:], os.Stdout, os.Stderr, audit)
	_ = telemetry.ShutdownDefault(context.Background())
	os.Exit(code)
}

func run(args []string, out, diagnostics io.Writer) int {
	return runWithAudit(args, out, diagnostics, nil)
}

func runWithAudit(args []string, out, diagnostics io.Writer, audit *slog.Logger) int {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		if audit != nil {
			audit.Warn("recording_admin_denied", "actor", fmt.Sprintf("uid:%d", os.Getuid()), "decision", "deny", "reason", "root_required")
		}
		_, _ = fmt.Fprintln(diagnostics, "recording-admin requires a root administrative console")
		return 2
	}
	for _, name := range []string{"SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"} {
		if _, set := os.LookupEnv(name); set {
			if audit != nil {
				audit.Warn("recording_admin_denied", "actor", "uid:0", "decision", "deny", "reason", "ssh_context")
			}
			_, _ = fmt.Fprintln(diagnostics, "recording-admin refuses SSH sessions")
			return 2
		}
	}
	return executeWithAudit(args, out, diagnostics, audit)
}

func execute(args []string, out, diagnostics io.Writer) int {
	return executeWithAudit(args, out, diagnostics, nil)
}

func executeWithAudit(args []string, out, diagnostics io.Writer, audit *slog.Logger) (exitCode int) {
	if len(args) > 0 && args[0] == "permissions" {
		code := executePermissions(args[1:], out, diagnostics)
		if audit != nil {
			action := "invalid"
			if len(args) > 1 && (args[1] == "plan" || args[1] == "apply" || args[1] == "rollback") {
				action = args[1]
			}
			decision := "deny"
			if code == 0 {
				decision = "allow"
			}
			audit.Info("recording_admin_permissions_result", "actor", fmt.Sprintf("uid:%d", os.Getuid()), "action", action, "decision", decision, "exit_code", code)
		}
		return code
	}
	if len(args) == 0 || args[0] != "seal" && args[0] != "verify" && args[0] != "decrypt" && args[0] != "verify-published" {
		_, _ = fmt.Fprintln(diagnostics, "usage: recording-admin seal|verify|decrypt|verify-published|permissions [flags]")
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet("recording-admin "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	input := flags.String("input", "", "Regular input file; stdin is not accepted")
	limit := flags.Int64("max-input-bytes", defaultInputLimit, "Maximum input file size (default 1 GiB)")
	var output, signingKey, sessionID, bastionID, protocol, account, target, startedAt, compression string
	var chunkSize int
	var recipients, verifyFiles, privateFiles fileFlags
	if command != "verify" && command != "verify-published" {
		flags.StringVar(&output, "output", "", "New output file in a private service-owned directory (never stdout)")
	}
	switch command {
	case "seal":
		flags.StringVar(&signingKey, "signing-key", "", "Dedicated Ed25519 PKCS8 private PEM file")
		flags.Var(&recipients, "recipient", "RSA PKIX public PEM recipient file; repeat for multiple recipients")
		flags.StringVar(&sessionID, "session-id", "", "Asserted historical session identifier")
		flags.StringVar(&bastionID, "bastion-id", "", "Asserted historical bastion identifier")
		flags.StringVar(&protocol, "protocol", "", "Asserted recording protocol")
		flags.StringVar(&account, "account", "", "Asserted account name (public metadata)")
		flags.StringVar(&target, "target", "", "Asserted target (public metadata; no credentials)")
		flags.StringVar(&startedAt, "started-at", "", "Asserted historical start time in RFC3339 format")
		flags.StringVar(&compression, "compression", "none", "Input encoding: none or gzip; input is not recompressed")
		flags.IntVar(&chunkSize, "chunk-size", archive.DefaultChunkSize, "Plaintext bytes per encrypted segment")
	case "verify-published":
		// Checks the best-effort SHA-256 sidecar emitted by live publication.
	default:
		flags.Var(&verifyFiles, "verify-key", "Trusted Ed25519 PKIX public PEM file; repeat for historical signers")
		if command == "decrypt" {
			flags.Var(&privateFiles, "recipient-key", "RSA PKCS8 private PEM file; repeat for historical recipients")
		}
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *input == "" || *input == "-" || *limit < 1 || *limit > maximumInputLimit || (command != "verify" && command != "verify-published" && (output == "" || output == "-")) {
		_, _ = fmt.Fprintln(diagnostics, "invalid input, output, size limit, or positional arguments")
		return 2
	}
	if command == "seal" && (signingKey == "" || len(recipients) == 0 || sessionID == "" || bastionID == "" || protocol == "" || startedAt == "") || (command == "verify" || command == "decrypt") && len(verifyFiles) == 0 || command == "decrypt" && len(privateFiles) == 0 {
		_, _ = fmt.Fprintln(diagnostics, "required key or provenance flags are missing")
		return 2
	}
	var manifest archive.Manifest
	ctx, span := telemetry.Start(context.Background(), "recording.archive", telemetry.Component("recording"))
	inputHash := sha256.Sum256([]byte(*input))
	if audit != nil {
		audit = audit.With("actor", fmt.Sprintf("uid:%d", os.Getuid()), "action", command, "target", "path-sha256:"+hex.EncodeToString(inputHash[:]))
		audit.InfoContext(ctx, "recording_admin_access", "decision", "attempt")
	}
	defer func() {
		if exitCode == 0 {
			span.Success()
		} else {
			span.Failure()
		}
		span.End()
		if audit != nil {
			decision := "deny"
			if exitCode == 0 {
				decision = "allow"
			}
			audit.InfoContext(ctx, "recording_admin_result", "decision", decision, "archive_id", manifest.ArchiveID(), "exit_code", exitCode)
		}
	}()
	var err error
	switch command {
	case "seal":
		var start time.Time
		start, err = time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			_, _ = fmt.Fprintln(diagnostics, "invalid start timestamp")
			return 2
		}
		manifest, err = sealFile(*input, output, signingKey, recipients, *limit, archive.Provenance{SessionID: sessionID, BastionID: bastionID, Protocol: protocol, Account: account, Target: target, StartedAt: start}, archive.Options{ChunkSize: chunkSize, Compression: compression})
	case "verify-published":
		err = verifyPublishedRecording(*input, *limit)
	default:
		var trusted []ed25519.PublicKey
		trusted, err = readVerificationKeys(verifyFiles)
		if err == nil {
			if command == "verify" {
				manifest, err = verifyFile(*input, *limit, trusted)
			} else {
				manifest, err = decryptFile(*input, output, *limit, trusted, privateFiles)
			}
		}
	}
	if err != nil {
		// Parser/OS errors can include file data or operator-supplied names. Keep
		// diagnostics bounded and never print keys, terminal content, or PEM data.
		_, _ = fmt.Fprintf(diagnostics, "%s failed; no unauthenticated output was published\n", command)
		return 1
	}
	if command == "verify-published" {
		if _, err := fmt.Fprintln(out, `{"status":"ok","integrity":"verified"}`); err != nil {
			return 1
		}
		return 0
	}
	if _, err := out.Write(append(manifest.CanonicalJSON(), '\n')); err != nil {
		return 1
	}
	return 0
}

func openRegular(path string, maximum int64) (*os.File, error) {
	return openRegularFlags(path, maximum, 0)
}

func openRegularFlags(path string, maximum int64, extraFlags int) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|extraFlags, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		_ = file.Close()
		return nil, errors.New("invalid regular input file")
	}
	return file, nil
}

func readKeyPEM(path string, private bool) (*pem.Block, error) {
	flags := syscall.O_NOFOLLOW
	file, err := openRegularFlags(path, keyFileLimit, flags)
	if err != nil {
		return nil, errors.New("cannot open key file")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect key file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("key file must be service-owned and protected from modification")
	}
	if private {
		if info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("private key file must be private and service-owned")
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, keyFileLimit+1))
	defer clear(data)
	if err != nil || len(data) > keyFileLimit {
		return nil, errors.New("cannot read key file")
	}
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return nil, errors.New("unexpected leading key data")
	}
	block, rest := pem.Decode(data)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || private && block.Type != "PRIVATE KEY" || !private && block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid key PEM")
	}
	canonical := pem.EncodeToMemory(block)
	defer clear(canonical)
	if !bytes.Equal(data, canonical) {
		clear(block.Bytes)
		return nil, errors.New("key file must contain exactly one canonical PEM block")
	}
	return block, nil
}

func readSigningKey(path string) (ed25519.PrivateKey, error) {
	block, err := readKeyPEM(path, true)
	if err != nil {
		return nil, err
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key must be Ed25519")
	}
	return key, nil
}

func readRecipients(paths []string) ([]*rsa.PublicKey, error) {
	keys := make([]*rsa.PublicKey, 0, len(paths))
	for _, path := range paths {
		block, err := readKeyPEM(path, false)
		if err != nil {
			return nil, err
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid recipient public key")
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("recipient key must be RSA")
		}
		if _, err := archive.RecipientKeyID(key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func readVerificationKeys(paths []string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(paths))
	for _, path := range paths {
		block, err := readKeyPEM(path, false)
		if err != nil {
			return nil, err
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid verification public key")
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("verification key must be Ed25519")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func readPrivateRecipients(paths []string) ([]*rsa.PrivateKey, error) {
	keys := make([]*rsa.PrivateKey, 0, len(paths))
	for _, path := range paths {
		block, err := readKeyPEM(path, true)
		if err != nil {
			return nil, err
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		clear(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid recipient private key")
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("recipient private key must be RSA")
		}
		if _, err := archive.RecipientKeyID(&key.PublicKey); err != nil {
			return nil, err
		}
		if err := key.Validate(); err != nil {
			return nil, errors.New("invalid RSA private key")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func sealFile(input, output, signingPath string, recipientPaths []string, limit int64, provenance archive.Provenance, options archive.Options) (archive.Manifest, error) {
	signer, err := readSigningKey(signingPath)
	if err != nil {
		return archive.Manifest{}, err
	}
	defer clear(signer)
	recipients, err := readRecipients(recipientPaths)
	if err != nil {
		return archive.Manifest{}, err
	}
	source, err := openRegular(input, limit)
	if err != nil {
		return archive.Manifest{}, err
	}
	defer func() { _ = source.Close() }()
	return atomicOutput(output, func(dst *os.File) (archive.Manifest, error) {
		writer, err := archive.NewWriter(dst, provenance, recipients, signer, options)
		if err != nil {
			return archive.Manifest{}, err
		}
		defer writer.Abort()
		n, err := io.Copy(writer, io.LimitReader(source, limit+1))
		if err != nil || n > limit {
			return archive.Manifest{}, errors.New("source read failed or size limit exceeded")
		}
		if err := writer.CloseWithOutcome(archive.OutcomeImported); err != nil {
			return archive.Manifest{}, err
		}
		return writer.Manifest()
	})
}

func verifyFile(input string, limit int64, trusted []ed25519.PublicKey) (archive.Manifest, error) {
	source, err := openRegular(input, limit)
	if err != nil {
		return archive.Manifest{}, err
	}
	defer func() { _ = source.Close() }()
	counted := &countingReader{Reader: io.LimitReader(source, limit+1)}
	manifest, err := archive.Verify(counted, trusted)
	if counted.bytes > limit {
		return archive.Manifest{}, errors.New("input size limit exceeded")
	}
	return manifest, err
}

type countingReader struct {
	io.Reader
	bytes int64
}

func (r *countingReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	r.bytes += int64(n)
	return n, err
}

func decryptFile(input, output string, limit int64, trusted []ed25519.PublicKey, paths []string) (archive.Manifest, error) {
	recipients, err := readPrivateRecipients(paths)
	if err != nil {
		return archive.Manifest{}, err
	}
	source, err := openRegular(input, limit)
	if err != nil {
		return archive.Manifest{}, err
	}
	defer func() { _ = source.Close() }()
	// Only ciphertext is copied. Unlink the private snapshot immediately so no
	// other pathname can mutate it between verification and decryption passes.
	snapshot, err := os.CreateTemp("", "gobastion-recording-ciphertext-*")
	if err != nil {
		return archive.Manifest{}, err
	}
	defer func() { _ = snapshot.Close() }()
	defer func() { _ = os.Remove(snapshot.Name()) }()
	if err := os.Remove(snapshot.Name()); err != nil {
		return archive.Manifest{}, err
	}
	n, err := io.Copy(snapshot, io.LimitReader(source, limit+1))
	if err != nil || n > limit {
		return archive.Manifest{}, errors.New("ciphertext snapshot failed or size limit exceeded")
	}
	return atomicOutput(output, func(dst *os.File) (archive.Manifest, error) {
		return archive.Decrypt(snapshot, n, dst, trusted, recipients)
	})
}

// atomicOutput keeps output private until authenticated completion. Directory
// descriptors anchor every operation; the exclusive hard link never replaces
// an existing filename. The service-owned parent excludes other writers.
func atomicOutput(path string, write func(*os.File) (archive.Manifest, error)) (archive.Manifest, error) {
	if path == "" || path == "-" {
		return archive.Manifest{}, errors.New("invalid output path")
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return archive.Manifest{}, err
	}
	defer func() { _ = parent.Close() }()
	info, err := parent.Stat(".")
	if err != nil {
		return archive.Manifest{}, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return archive.Manifest{}, errors.New("output directory must be private and service-owned")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return archive.Manifest{}, err
	}
	name := ".recording-admin-" + hex.EncodeToString(random[:])
	file, err := parent.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return archive.Manifest{}, err
	}
	defer func() { _ = file.Close() }()
	defer func() { _ = parent.Remove(name) }()
	manifest, err := write(file)
	if err != nil {
		return archive.Manifest{}, err
	}
	if err := file.Sync(); err != nil {
		return archive.Manifest{}, err
	}
	if err := file.Close(); err != nil {
		return archive.Manifest{}, err
	}
	if err := parent.Link(name, filepath.Base(path)); err != nil {
		return archive.Manifest{}, err
	}
	dir, err := parent.Open(".")
	if err != nil {
		return archive.Manifest{}, err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return archive.Manifest{}, err
	}
	return manifest, nil
}

func verifyPublishedRecording(input string, limit int64) error {
	return recording.VerifyPublishedIntegrityWithLimit(input, limit)
}
