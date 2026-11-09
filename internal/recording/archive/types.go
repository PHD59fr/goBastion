package archive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	Version          = 1
	DefaultChunkSize = 64 << 10
	MaxChunkSize     = 1 << 20
	MaxSegments      = 1 << 20
	MaxRecipients    = 32
	maxJSONBytes     = 64 << 10
	frameHeaderBytes = 13
	gcmOverhead      = 28
	magic            = "GOBREC01"
	manifestDomain   = "goBastion recording manifest v1\x00"
	frameDomain      = "goBastion recording frame v1\x00"
	wrapDomain       = "goBastion recording data key v1\x00"
)

var (
	ErrInvalidArchive       = errors.New("invalid recording archive")
	ErrInvalidKey           = errors.New("invalid recording archive key")
	ErrUntrustedSigner      = errors.New("recording signer is not trusted")
	ErrRecipientUnavailable = errors.New("recording recipient key unavailable or invalid")
	ErrLimit                = errors.New("recording archive limit exceeded")
	ErrClosed               = errors.New("recording archive writer is closed")
	ErrIncomplete           = errors.New("recording archive is not finalized")
)

// Provenance is supplied by the trusted recorder. These fields are public,
// signed metadata; do not place credentials or terminal content in them.
type Provenance struct {
	SessionID string    `json:"session_id"`
	BastionID string    `json:"bastion_id"`
	Protocol  string    `json:"protocol"`
	Account   string    `json:"account"`
	Target    string    `json:"target"`
	StartedAt time.Time `json:"started_at"`
}

// Options describes the input stream. Compression is "none" (default) or
// "gzip"; the caller supplies already compressed bytes when selecting gzip.
type Options struct {
	ChunkSize   int
	Compression string
}

// CaptureOutcome is a signed assertion by the finalizing service, not proof of
// a truthful or complete capture. Importing legacy bytes cannot establish their
// historical provenance. This API does not automatically recover prefixes.
type CaptureOutcome string

const (
	OutcomeUnspecified       CaptureOutcome = "unspecified"
	OutcomeImported          CaptureOutcome = "imported"
	OutcomeComplete          CaptureOutcome = "complete"
	OutcomeInterruptedPrefix CaptureOutcome = "interrupted-prefix"
)

func validOutcome(outcome CaptureOutcome) bool {
	switch outcome {
	case OutcomeUnspecified, OutcomeImported, OutcomeComplete, OutcomeInterruptedPrefix:
		return true
	default:
		return false
	}
}

type contextData struct {
	Version      int        `json:"version"`
	ArchiveID    string     `json:"archive_id"`
	Cipher       string     `json:"cipher"`
	KeyWrap      string     `json:"key_wrap"`
	Signature    string     `json:"signature"`
	ContentType  string     `json:"content_type"`
	Compression  string     `json:"compression"`
	ChunkSize    int        `json:"chunk_size"`
	SignerKeyID  string     `json:"signer_key_id"`
	RecipientIDs []string   `json:"recipient_key_ids"`
	Provenance   Provenance `json:"provenance"`
}

type wrappedRecipient struct {
	KeyID      string `json:"key_id"`
	WrappedKey string `json:"wrapped_key"`
}

type headerData struct {
	Context    contextData        `json:"context"`
	Recipients []wrappedRecipient `json:"recipients"`
}

type manifestData struct {
	Context          contextData    `json:"context"`
	HeaderSHA256     string         `json:"header_sha256"`
	CiphertextSHA256 string         `json:"ciphertext_sha256"`
	Segments         uint64         `json:"segments"`
	PlaintextBytes   uint64         `json:"plaintext_bytes"`
	CiphertextBytes  uint64         `json:"ciphertext_bytes"`
	CaptureOutcome   CaptureOutcome `json:"capture_outcome"`
	FinalizedAt      time.Time      `json:"finalized_at"`
}

// Manifest is an immutable view of a signed manifest. Accessors return values
// or independent copies. A zero Manifest represents no authenticated archive.
type Manifest struct {
	data      manifestData
	canonical []byte
	signature []byte
}

func (m Manifest) CanonicalJSON() []byte  { return bytes.Clone(m.canonical) }
func (m Manifest) Signature() []byte      { return bytes.Clone(m.signature) }
func (m Manifest) Provenance() Provenance { return m.data.Context.Provenance }
func (m Manifest) ArchiveID() string      { return m.data.Context.ArchiveID }
func (m Manifest) SignerKeyID() string    { return m.data.Context.SignerKeyID }
func (m Manifest) RecipientKeyIDs() []string {
	return append([]string(nil), m.data.Context.RecipientIDs...)
}
func (m Manifest) Compression() string            { return m.data.Context.Compression }
func (m Manifest) HeaderSHA256() string           { return m.data.HeaderSHA256 }
func (m Manifest) CiphertextSHA256() string       { return m.data.CiphertextSHA256 }
func (m Manifest) Segments() uint64               { return m.data.Segments }
func (m Manifest) PlaintextBytes() uint64         { return m.data.PlaintextBytes }
func (m Manifest) CiphertextBytes() uint64        { return m.data.CiphertextBytes }
func (m Manifest) FinalizedAt() time.Time         { return m.data.FinalizedAt }
func (m Manifest) CaptureOutcome() CaptureOutcome { return m.data.CaptureOutcome }

// SigningKeyID fingerprints an Ed25519 public key. IDs do not establish trust.
func SigningKeyID(key ed25519.PublicKey) (string, error) {
	if len(key) != ed25519.PublicKeySize {
		return "", ErrInvalidKey
	}
	sum := sha256.Sum256(key)
	return "ed25519-sha256:" + hex.EncodeToString(sum[:]), nil
}

// RecipientKeyID fingerprints the PKIX encoding of an accepted RSA public key.
func RecipientKeyID(key *rsa.PublicKey) (string, error) {
	if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.BitLen() < 3072 || key.N.BitLen() > 8192 || key.N.Bit(0) == 0 || key.E != 65537 {
		return "", ErrInvalidKey
	}
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", ErrInvalidKey
	}
	sum := sha256.Sum256(encoded)
	return "rsa-sha256:" + hex.EncodeToString(sum[:]), nil
}

func validFingerprint(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return validHex(strings.TrimPrefix(value, prefix), sha256.Size)
}

func validHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}

func validText(value string, maximum int, required bool) bool {
	if len(value) > maximum || !utf8.ValidString(value) || required && value == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}

func validateContext(c contextData) error {
	if c.Version != Version || c.Cipher != "AES-256-GCM" || c.KeyWrap != "RSA-OAEP-SHA256" || c.Signature != "Ed25519" || c.ContentType != "ttyrec" || c.Compression != "none" && c.Compression != "gzip" || c.ChunkSize < 1 || c.ChunkSize > MaxChunkSize || !validHex(c.ArchiveID, 16) || !validFingerprint(c.SignerKeyID, "ed25519-sha256:") {
		return ErrInvalidArchive
	}
	if len(c.RecipientIDs) < 1 || len(c.RecipientIDs) > MaxRecipients {
		return ErrInvalidArchive
	}
	for i, id := range c.RecipientIDs {
		if !validFingerprint(id, "rsa-sha256:") || i > 0 && c.RecipientIDs[i-1] >= id {
			return ErrInvalidArchive
		}
	}
	p := c.Provenance
	if !validText(p.SessionID, 128, true) || !validText(p.BastionID, 128, true) || !validText(p.Protocol, 32, true) || !validText(p.Account, 128, false) || !validText(p.Target, 1024, false) || !validTime(p.StartedAt) {
		return ErrInvalidArchive
	}
	return nil
}

func decodeCanonical(data []byte, value any) error {
	if len(data) == 0 || len(data) > maxJSONBytes {
		return ErrInvalidArchive
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalidArchive
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidArchive
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrInvalidArchive
	}
	return nil
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidArchive
	}
	return decoded, nil
}

func validateHeader(h headerData) error {
	if err := validateContext(h.Context); err != nil {
		return err
	}
	if len(h.Recipients) != len(h.Context.RecipientIDs) {
		return ErrInvalidArchive
	}
	for i, recipient := range h.Recipients {
		if recipient.KeyID != h.Context.RecipientIDs[i] || len(recipient.WrappedKey) > base64.StdEncoding.EncodedLen(1024) {
			return ErrInvalidArchive
		}
		wrapped, err := decodeBase64(recipient.WrappedKey)
		if err != nil || len(wrapped) < 384 || len(wrapped) > 1024 {
			return ErrInvalidArchive
		}
	}
	return nil
}

func validateManifest(m manifestData) error {
	if err := validateContext(m.Context); err != nil {
		return err
	}
	if !validHex(m.HeaderSHA256, sha256.Size) || !validHex(m.CiphertextSHA256, sha256.Size) || !validTime(m.FinalizedAt) || !validOutcome(m.CaptureOutcome) || m.Segments > MaxSegments {
		return ErrInvalidArchive
	}
	if m.Segments == 0 {
		if m.PlaintextBytes != 0 || m.CiphertextBytes != 0 {
			return ErrInvalidArchive
		}
	} else if m.PlaintextBytes <= (m.Segments-1)*uint64(m.Context.ChunkSize) || m.PlaintextBytes > m.Segments*uint64(m.Context.ChunkSize) {
		return ErrInvalidArchive
	}
	if m.CiphertextBytes != m.PlaintextBytes+m.Segments*(frameHeaderBytes+gcmOverhead) {
		return ErrInvalidArchive
	}
	return nil
}

func trustedSigner(id string, trusted []ed25519.PublicKey) (ed25519.PublicKey, error) {
	if len(trusted) > 256 {
		return nil, ErrLimit
	}
	for _, key := range trusted {
		keyID, err := SigningKeyID(key)
		if err != nil {
			return nil, err
		}
		if keyID == id {
			return bytes.Clone(key), nil
		}
	}
	return nil, ErrUntrustedSigner
}

// VerifyManifest authenticates a standalone canonical manifest. It verifies its
// signed assertions, not that an associated ciphertext stream matches them;
// use Verify to authenticate the complete archive.
func VerifyManifest(data, signature []byte, trusted []ed25519.PublicKey) (Manifest, error) {
	var m manifestData
	if err := decodeCanonical(data, &m); err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	key, err := trustedSigner(m.Context.SignerKeyID, trusted)
	if err != nil {
		return Manifest{}, err
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(manifestDomain), data...), signature) {
		return Manifest{}, fmt.Errorf("%w: signature verification failed", ErrInvalidArchive)
	}
	return Manifest{m, bytes.Clone(data), bytes.Clone(signature)}, nil
}
