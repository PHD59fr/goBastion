package recording

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"goBastion/internal/recording/archive"
	"golang.org/x/sys/unix"
)

// LivePolicyPath is deliberately outside the account-editable application
// configuration. Creating this root-owned policy requires encrypted captures.
const LivePolicyPath = "/etc/gobastion/recording-live.json"

const liveKeyLimit = 64 << 10

type livePolicyConfig struct {
	Version    int      `json:"version"`
	SigningKey string   `json:"signing_key"`
	Recipients []string `json:"recipients"`
	ChunkSize  int      `json:"chunk_size,omitempty"`
}

// LivePolicy contains the dedicated signer and public encryption recipients.
// Only the privileged recorder may load it. It never contains decryption keys.
type LivePolicy struct {
	signer     ed25519.PrivateKey
	recipients []*rsa.PublicKey
	chunkSize  int
}

func (p *LivePolicy) Close() {
	if p != nil {
		clear(p.signer)
		p.signer = nil
	}
}

// LoadLivePolicy returns nil only when no policy exists. An inaccessible,
// malformed or unsafe policy is an error; it never enables plaintext fallback.
// Ordinary SSH recorders cannot use the root-only signing key and are denied
// while a policy exists, pending a trusted SSH recording supervisor. The current
// supported encrypted path is the root DB recorder. Raw spools remain plaintext;
// interrupted encrypted spools require administrative recovery.
func LoadLivePolicy() (*LivePolicy, error) {
	root, err := os.Open("/")
	if err != nil {
		return nil, errors.New("cannot inspect live recording policy")
	}
	defer func() { _ = root.Close() }()
	return loadLivePolicy(root, LivePolicyPath, 0, os.Geteuid() == 0)
}

func loadLivePolicy(root *os.File, path string, owner int, privileged bool) (*LivePolicy, error) {
	data, err := readLiveFile(root, path, owner, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("unsafe or unavailable live recording policy")
	}
	if !privileged {
		return nil, errors.New("encrypted recording requires a trusted recording supervisor")
	}
	var cfg livePolicyConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || cfg.Version != 1 || cfg.SigningKey == "" || len(cfg.Recipients) == 0 || len(cfg.Recipients) > archive.MaxRecipients || cfg.ChunkSize < 0 || cfg.ChunkSize > archive.MaxChunkSize {
		return nil, errors.New("invalid live recording policy")
	}
	block, err := readLivePEM(root, cfg.SigningKey, owner, true)
	if err != nil {
		return nil, errors.New("invalid live recording signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block)
	clear(block)
	if err != nil {
		return nil, errors.New("invalid live recording signing key")
	}
	signer, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid live recording signing key")
	}
	policy := &LivePolicy{signer: signer, chunkSize: cfg.ChunkSize}
	loaded := false
	defer func() {
		if !loaded {
			policy.Close()
		}
	}()
	seen := make(map[string]bool)
	for _, path := range cfg.Recipients {
		block, err := readLivePEM(root, path, owner, false)
		if err != nil {
			return nil, errors.New("invalid live recording recipient")
		}
		parsed, err := x509.ParsePKIXPublicKey(block)
		if err != nil {
			return nil, errors.New("invalid live recording recipient")
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid live recording recipient")
		}
		id, err := archive.RecipientKeyID(key)
		if err != nil || seen[id] {
			return nil, errors.New("invalid or duplicate live recording recipient")
		}
		seen[id] = true
		policy.recipients = append(policy.recipients, key)
	}
	loaded = true
	return policy, nil
}

// readLiveFile traverses every ancestor through held no-follow descriptors.
// The policy and all keys must remain under trusted, non-writable directories.
func readLiveFile(root *os.File, path string, owner int, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("invalid recording key path")
	}
	ownerID, err := checkedUnixOwnerID(owner)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Dup(int(root.Fd()))
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	defer func() { _ = unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != ownerID || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0022 != 0 {
			return nil, errors.New("untrusted recording key ancestor")
		}
		if err := ValidateNoACL(fd); err != nil {
			return nil, err
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		if i != len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return nil, err
		}
		_ = unix.Close(fd)
		fd = next
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != ownerID || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 || private && stat.Mode&0077 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > liveKeyLimit {
		return nil, errors.New("unsafe recording key file")
	}
	if err := ValidateNoACL(fd); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "recording-policy")
	// Transfer descriptor ownership so the deferred close above cannot close a
	// subsequently reused descriptor after file.Close.
	fd = -1
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, liveKeyLimit+1))
	if err != nil || len(data) > liveKeyLimit {
		clear(data)
		return nil, errors.New("cannot read recording key file")
	}
	return data, nil
}

func checkedUnixOwnerID(owner int) (uint32, error) {
	if owner < 0 || uint64(owner) > uint64(^uint32(0)) {
		return 0, errors.New("invalid recording key owner")
	}
	return uint32(owner), nil
}

func readLivePEM(root *os.File, path string, owner int, private bool) ([]byte, error) {
	data, err := readLiveFile(root, path, owner, private)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	typeName := "PUBLIC KEY"
	if private {
		typeName = "PRIVATE KEY"
	}
	if block == nil || block.Type != typeName || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, errors.New("invalid recording key PEM")
	}
	canonical := pem.EncodeToMemory(block)
	defer clear(canonical)
	if !bytes.Equal(data, canonical) {
		clear(block.Bytes)
		return nil, errors.New("noncanonical recording key PEM")
	}
	return block.Bytes, nil
}

// CaptureWriter compresses each block and, with a nonnil policy, encrypts it
// before it reaches dst. ttyrec's separate raw spool is still plaintext.
type CaptureWriter struct {
	gzip      *gzip.Writer
	encrypted *archive.Writer
	closed    bool
	err       error
}

func NewCaptureWriter(dst io.Writer, policy *LivePolicy, provenance archive.Provenance) (*CaptureWriter, error) {
	writer := &CaptureWriter{}
	if policy != nil {
		encrypted, err := archive.NewWriter(dst, provenance, policy.recipients, policy.signer, archive.Options{Compression: "gzip", ChunkSize: policy.chunkSize, Streaming: true})
		if err != nil {
			return nil, fmt.Errorf("initialize encrypted recording: %w", err)
		}
		writer.encrypted = encrypted
		dst = encrypted
	}
	writer.gzip = gzip.NewWriter(dst)
	return writer, nil
}

func (w *CaptureWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, archive.ErrClosed
	}
	n, err := w.gzip.Write(p)
	if err != nil {
		_ = w.fail(err)
	}
	return n, err
}

func (w *CaptureWriter) fail(err error) error {
	w.err = err
	if w.encrypted != nil {
		w.encrypted.Abort()
	}
	return err
}

func (w *CaptureWriter) Flush() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return archive.ErrClosed
	}
	if err := w.gzip.Flush(); err != nil {
		return w.fail(err)
	}
	if w.encrypted != nil {
		if err := w.encrypted.Flush(); err != nil {
			return w.fail(err)
		}
	}
	return nil
}

func (w *CaptureWriter) CloseWithOutcome(outcome archive.CaptureOutcome) error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return archive.ErrClosed
	}
	w.closed = true
	if err := w.gzip.Close(); err != nil {
		return w.fail(err)
	}
	if w.encrypted != nil {
		if err := w.encrypted.CloseWithOutcome(outcome); err != nil {
			return w.fail(err)
		}
	}
	return nil
}

func (w *CaptureWriter) Abort() {
	if !w.closed {
		_ = w.fail(archive.ErrIncomplete)
	}
}

// CloseAfterRecorder signs complete only when the recorder and its session
// context both ended successfully. Cancellation and even otherwise accepted
// nonzero exits conservatively describe a captured prefix, never completeness.
// Capture/recorder-completion failures must abort instead of calling this method.
func (w *CaptureWriter) CloseAfterRecorder(commandErr, contextErr error) error {
	outcome := archive.OutcomeComplete
	if commandErr != nil || contextErr != nil {
		outcome = archive.OutcomeInterruptedPrefix
	}
	return w.CloseWithOutcome(outcome)
}
