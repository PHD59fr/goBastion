package recording

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const integrityManifestLimit int64 = 64 << 10
const defaultIntegrityInputLimit int64 = 1 << 30

// VerifyPublishedIntegrity checks a published recording against its best-effort
// SHA-256 sidecar, with a 1 GiB recording limit. A missing or invalid sidecar is
// reported as an error. The unsigned sidecar does not authenticate provenance.
func VerifyPublishedIntegrity(path string) error {
	return VerifyPublishedIntegrityWithLimit(path, defaultIntegrityInputLimit)
}

// VerifyPublishedIntegrityWithLimit bounds both reads on held regular-file
// descriptors. Pinning the parent also keeps the recording and its sidecar in
// the same directory if an account concurrently renames its namespace.
func VerifyPublishedIntegrityWithLimit(path string, limit int64) error {
	if limit < 1 || limit == 1<<63-1 {
		return fmt.Errorf("invalid recording size limit")
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open recording directory: %w", err)
	}
	defer func() { _ = parent.Close() }()
	f, err := openIntegrityInput(parent, filepath.Base(path), limit)
	if err != nil {
		return fmt.Errorf("open recording: %w", err)
	}
	defer func() { _ = f.Close() }()
	manifest, err := openIntegrityInput(parent, publishIntegrityName(path), integrityManifestLimit)
	if err != nil {
		return fmt.Errorf("open integrity manifest: %w", err)
	}
	defer func() { _ = manifest.Close() }()
	mf, err := io.ReadAll(io.LimitReader(manifest, integrityManifestLimit+1))
	if err != nil {
		return fmt.Errorf("read integrity manifest: %w", err)
	}
	if int64(len(mf)) > integrityManifestLimit {
		return fmt.Errorf("integrity manifest size limit exceeded")
	}
	var m publishIntegrityManifest
	if err := json.Unmarshal(mf, &m); err != nil {
		return fmt.Errorf("parse integrity manifest: %w", err)
	}
	digest, err := hex.DecodeString(m.SHA256)
	if m.Version != 1 || m.Algorithm != "sha256" || m.Size < 0 || m.Size > limit || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != m.SHA256 {
		return fmt.Errorf("unsupported integrity manifest")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return fmt.Errorf("hash recording: %w", err)
	}
	if n > limit {
		return fmt.Errorf("recording size limit exceeded")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if n != m.Size || sum != m.SHA256 {
		return fmt.Errorf("integrity mismatch for %s", filepath.Base(path))
	}
	return nil
}

func openIntegrityInput(parent *os.Root, name string, limit int64) (*os.File, error) {
	f, err := parent.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		_ = f.Close()
		return nil, fmt.Errorf("invalid regular integrity input")
	}
	return f, nil
}
