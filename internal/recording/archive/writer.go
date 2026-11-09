package archive

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"sort"
	"time"
)

// Writer buffers at most one plaintext chunk. It is not safe for concurrent
// use. Close finalizes and signs the stream without closing the destination.
// A partial/failed writer output must never be published as a complete archive.
type Writer struct {
	dst                             io.Writer
	aead                            cipher.AEAD
	signer                          ed25519.PrivateKey
	context                         contextData
	headerHash                      [sha256.Size]byte
	hash                            hash.Hash
	buffer                          []byte
	segments, plaintext, ciphertext uint64
	closed                          bool
	err                             error
	manifest                        Manifest
}

// NewWriter validates all key material before writing the archive header. Public
// recipients cannot decrypt one another's wrapped data keys. The signing key
// must be dedicated to recording provenance, independent of recipient keys.
func NewWriter(dst io.Writer, provenance Provenance, recipients []*rsa.PublicKey, signer ed25519.PrivateKey, options Options) (*Writer, error) {
	if dst == nil {
		return nil, ErrInvalidArchive
	}
	if len(signer) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(signer[:ed25519.SeedSize]), signer) {
		return nil, ErrInvalidKey
	}
	if len(recipients) < 1 || len(recipients) > MaxRecipients {
		return nil, ErrInvalidKey
	}
	if options.ChunkSize == 0 {
		options.ChunkSize = DefaultChunkSize
	}
	if options.Compression == "" {
		options.Compression = "none"
	}
	ids := make([]string, 0, len(recipients))
	byID := make(map[string]*rsa.PublicKey, len(recipients))
	for _, key := range recipients {
		id, err := RecipientKeyID(key)
		if err != nil {
			return nil, err
		}
		if _, duplicate := byID[id]; duplicate {
			return nil, ErrInvalidKey
		}
		byID[id] = key
		ids = append(ids, id)
	}
	sort.Strings(ids)
	signerID, _ := SigningKeyID(ed25519.PublicKey(signer[ed25519.SeedSize:]))
	var archiveID [16]byte
	if _, err := rand.Read(archiveID[:]); err != nil {
		return nil, err
	}
	provenance.StartedAt = provenance.StartedAt.UTC()
	context := contextData{Version, hex.EncodeToString(archiveID[:]), "AES-256-GCM", "RSA-OAEP-SHA256", "Ed25519", "ttyrec", options.Compression, options.ChunkSize, signerID, ids, provenance}
	if err := validateContext(context); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	header := headerData{Context: context}
	for _, id := range ids {
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, byID[id], key, wrapLabel(context, id))
		if err != nil {
			return nil, ErrInvalidKey
		}
		header.Recipients = append(header.Recipients, wrappedRecipient{id, base64.StdEncoding.EncodeToString(wrapped)})
	}
	encoded, err := json.Marshal(header)
	if err != nil || len(encoded) > maxJSONBytes {
		return nil, ErrLimit
	}
	prefix := make([]byte, len(magic)+4)
	copy(prefix, magic)
	binary.BigEndian.PutUint32(prefix[len(magic):], uint32(len(encoded)))
	headerBytes := append(prefix, encoded...)
	if err := writeFull(dst, headerBytes); err != nil {
		return nil, err
	}
	return &Writer{dst: dst, aead: aead, signer: bytes.Clone(signer), context: context, headerHash: sha256.Sum256(headerBytes), hash: sha256.New(), buffer: make([]byte, 0, options.ChunkSize)}, nil
}

func wrapLabel(context contextData, recipientID string) []byte {
	encoded, _ := json.Marshal(context)
	sum := sha256.Sum256(encoded)
	label := append([]byte(wrapDomain), sum[:]...)
	return append(label, recipientID...)
}

func frameAAD(headerHash [sha256.Size]byte, index uint64, length uint32) []byte {
	aad := make([]byte, len(frameDomain)+sha256.Size+12)
	copy(aad, frameDomain)
	copy(aad[len(frameDomain):], headerHash[:])
	binary.BigEndian.PutUint64(aad[len(frameDomain)+sha256.Size:], index)
	binary.BigEndian.PutUint32(aad[len(frameDomain)+sha256.Size+8:], length)
	return aad
}

func writeFull(dst io.Writer, data []byte) error {
	n, err := dst.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (w *Writer) fail(err error) error {
	w.err = err
	clear(w.buffer)
	w.buffer = nil
	clear(w.signer)
	w.signer = nil
	w.aead = nil
	return err
}

func (w *Writer) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, ErrClosed
	}
	accepted := 0
	for len(data) > 0 {
		if w.segments >= MaxSegments {
			return accepted, w.fail(ErrLimit)
		}
		n := min(w.context.ChunkSize-len(w.buffer), len(data))
		w.buffer = append(w.buffer, data[:n]...)
		accepted += n
		data = data[n:]
		if len(w.buffer) == w.context.ChunkSize {
			if err := w.flush(); err != nil {
				return accepted, w.fail(err)
			}
		}
	}
	return accepted, nil
}

func (w *Writer) flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	if w.segments >= MaxSegments {
		return ErrLimit
	}
	length := uint32(len(w.buffer) + w.aead.Overhead())
	encoded := w.aead.Seal(nil, nil, w.buffer, frameAAD(w.headerHash, w.segments, length))
	var prefix [frameHeaderBytes]byte
	prefix[0] = 1
	binary.BigEndian.PutUint64(prefix[1:9], w.segments)
	binary.BigEndian.PutUint32(prefix[9:13], length)
	if err := writeFull(w.dst, prefix[:]); err != nil {
		return err
	}
	if err := writeFull(w.dst, encoded); err != nil {
		return err
	}
	_, _ = w.hash.Write(prefix[:])
	_, _ = w.hash.Write(encoded)
	w.segments++
	w.plaintext += uint64(len(w.buffer))
	w.ciphertext += uint64(len(prefix) + len(encoded))
	clear(w.buffer)
	w.buffer = w.buffer[:0]
	return nil
}

func (w *Writer) Close() error {
	if w.closed && w.err == nil {
		return nil
	}
	return w.CloseWithOutcome(OutcomeUnspecified)
}

// CloseWithOutcome signs the caller's capture outcome. Complete is a recorder
// assertion, not a package guarantee. Invalid outcomes permanently fail the
// writer before flushing. A different outcome after finalization is rejected.
func (w *Writer) CloseWithOutcome(outcome CaptureOutcome) error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		if w.manifest.CaptureOutcome() == outcome {
			return nil
		}
		return ErrClosed
	}
	if !validOutcome(outcome) {
		return w.fail(ErrInvalidArchive)
	}
	w.closed = true
	if err := w.flush(); err != nil {
		return w.fail(err)
	}
	m := manifestData{w.context, hex.EncodeToString(w.headerHash[:]), hex.EncodeToString(w.hash.Sum(nil)), w.segments, w.plaintext, w.ciphertext, outcome, time.Now().UTC()}
	encoded, err := json.Marshal(m)
	if err != nil || len(encoded) > maxJSONBytes {
		return w.fail(ErrLimit)
	}
	signature := ed25519.Sign(w.signer, append([]byte(manifestDomain), encoded...))
	var prefix [5]byte
	prefix[0] = 2
	binary.BigEndian.PutUint32(prefix[1:], uint32(len(encoded)))
	for _, data := range [][]byte{prefix[:], encoded, signature} {
		if err := writeFull(w.dst, data); err != nil {
			return w.fail(err)
		}
	}
	w.manifest = Manifest{m, bytes.Clone(encoded), bytes.Clone(signature)}
	clear(w.signer)
	w.signer = nil
	w.buffer = nil
	w.aead = nil
	return nil
}

// Manifest returns an independent, immutable view after successful Close.
func (w *Writer) Manifest() (Manifest, error) {
	if w.err != nil {
		return Manifest{}, w.err
	}
	if !w.closed {
		return Manifest{}, ErrIncomplete
	}
	return w.manifest, nil
}

// Abort discards buffered plaintext and key copies after a source/capture error.
// It leaves an unfinalized ciphertext prefix, which must not be published as a
// complete archive. Calling Abort after successful Close has no effect.
func (w *Writer) Abort() {
	if !w.closed && w.err == nil {
		w.closed = true
		_ = w.fail(ErrIncomplete)
	}
}
