package archive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

var fixtureKeys struct {
	once sync.Once
	rsa  [3]*rsa.PrivateKey
	sign [2]ed25519.PrivateKey
	err  error
}

func archiveKeys(t *testing.T) ([3]*rsa.PrivateKey, [2]ed25519.PrivateKey) {
	t.Helper()
	fixtureKeys.once.Do(func() {
		for i := range fixtureKeys.rsa {
			fixtureKeys.rsa[i], fixtureKeys.err = rsa.GenerateKey(rand.Reader, 3072)
			if fixtureKeys.err != nil {
				return
			}
		}
		for i := range fixtureKeys.sign {
			_, fixtureKeys.sign[i], fixtureKeys.err = ed25519.GenerateKey(rand.Reader)
			if fixtureKeys.err != nil {
				return
			}
		}
	})
	if fixtureKeys.err != nil {
		t.Fatal("generate ephemeral test keys:", fixtureKeys.err)
	}
	return fixtureKeys.rsa, fixtureKeys.sign
}

func fixtureProvenance() Provenance {
	return Provenance{"session-1", "bastion-1", "ssh", "alice", "deploy@host.example:22", time.Date(2026, 11, 8, 1, 2, 3, 4, time.UTC)}
}

func fixturePayload() []byte { return bytes.Repeat([]byte("recorded terminal bytes\x00\xff\n"), 10) }

func createArchive(t *testing.T, plaintext []byte, recipients []*rsa.PublicKey, signer ed25519.PrivateKey) ([]byte, Manifest) {
	t.Helper()
	var dst bytes.Buffer
	w, err := NewWriter(&dst, fixtureProvenance(), recipients, signer, Options{ChunkSize: 32, Compression: "gzip"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Manifest(); !errors.Is(err, ErrIncomplete) {
		t.Fatal("unfinished writer exposed manifest")
	}
	for start := 0; start < len(plaintext); {
		end := min(start+7, len(plaintext))
		n, err := w.Write(plaintext[start:end])
		if err != nil || n != end-start {
			t.Fatal("write archive:", err)
		}
		start = end
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal("idempotent close:", err)
	}
	if _, err := w.Write([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatal("write after close accepted")
	}
	m, err := w.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	return dst.Bytes(), m
}

func signerPublic(private ed25519.PrivateKey) ed25519.PublicKey {
	return private.Public().(ed25519.PublicKey)
}

func archiveParts(t *testing.T, data []byte) ([]byte, [][]byte, []byte) {
	t.Helper()
	pos := len(magic) + 4 + int(binary.BigEndian.Uint32(data[len(magic):len(magic)+4]))
	header := bytes.Clone(data[:pos])
	var frames [][]byte
	for data[pos] == 1 {
		end := pos + frameHeaderBytes + int(binary.BigEndian.Uint32(data[pos+9:pos+13]))
		frames = append(frames, bytes.Clone(data[pos:end]))
		pos = end
	}
	if data[pos] != 2 {
		t.Fatal("fixture missing trailer")
	}
	return header, frames, bytes.Clone(data[pos:])
}

func joinArchive(header []byte, frames [][]byte, trailer []byte) []byte {
	result := bytes.Clone(header)
	for _, frame := range frames {
		result = append(result, frame...)
	}
	return append(result, trailer...)
}

func TestArchiveRoundTripAndIndependentPublicVerification(t *testing.T) {
	keys, signers := archiveKeys(t)
	plain := fixturePayload()
	data, written := createArchive(t, plain, []*rsa.PublicKey{&keys[1].PublicKey, &keys[0].PublicKey}, signers[0])
	trusted := []ed25519.PublicKey{signerPublic(signers[0])}
	verified, err := Verify(bytes.NewReader(data), trusted)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Provenance() != fixtureProvenance() || verified.Compression() != "gzip" || verified.PlaintextBytes() != uint64(len(plain)) || verified.Segments() != uint64((len(plain)+31)/32) || !bytes.Equal(written.CanonicalJSON(), verified.CanonicalJSON()) {
		t.Fatal("signed recording metadata changed")
	}
	if bytes.Contains(data, plain) {
		t.Fatal("archive contains plaintext")
	}
	for _, recipient := range keys[:2] {
		var decoded bytes.Buffer
		m, err := Decrypt(bytes.NewReader(data), int64(len(data)), &decoded, trusted, []*rsa.PrivateKey{recipient})
		if err != nil || !bytes.Equal(decoded.Bytes(), plain) || !bytes.Equal(m.CanonicalJSON(), verified.CanonicalJSON()) {
			t.Fatal("recipient round trip failed:", err)
		}
	}
	if _, err := VerifyManifest(verified.CanonicalJSON(), verified.Signature(), trusted); err != nil {
		t.Fatal("standalone manifest:", err)
	}
}

func TestArchiveKeysRotateIndependentlyAndDataKeysAreUnique(t *testing.T) {
	keys, signers := archiveKeys(t)
	plain := fixturePayload()
	old, oldManifest := createArchive(t, plain, []*rsa.PublicKey{&keys[0].PublicKey}, signers[0])
	rotated, newManifest := createArchive(t, plain, []*rsa.PublicKey{&keys[0].PublicKey, &keys[1].PublicKey}, signers[1])
	trusted := []ed25519.PublicKey{signerPublic(signers[0]), signerPublic(signers[1])}
	for _, data := range [][]byte{old, rotated} {
		if _, err := Verify(bytes.NewReader(data), trusted); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Verify(bytes.NewReader(old), trusted[1:]); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatal("retired signer unexpectedly trusted")
	}
	if oldManifest.ArchiveID() == newManifest.ArchiveID() || oldManifest.SignerKeyID() == newManifest.SignerKeyID() || oldManifest.CiphertextSHA256() == newManifest.CiphertextSHA256() {
		t.Fatal("rotation reused archive identities or ciphertext")
	}
	for _, recipient := range keys[:2] {
		var decoded bytes.Buffer
		if _, err := Decrypt(bytes.NewReader(rotated), int64(len(rotated)), &decoded, trusted, []*rsa.PrivateKey{recipient}); err != nil || !bytes.Equal(decoded.Bytes(), plain) {
			t.Fatal("rotation recipient failed:", err)
		}
	}
	second, _ := createArchive(t, plain, []*rsa.PublicKey{&keys[0].PublicKey}, signers[0])
	firstHeader, _, err := readHeader(bytes.NewReader(old))
	if err != nil {
		t.Fatal(err)
	}
	secondHeader, _, err := readHeader(bytes.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	unwrap := func(header headerData) []byte {
		wrapped, err := decodeBase64(header.Recipients[0].WrappedKey)
		if err != nil {
			t.Fatal(err)
		}
		key, err := rsa.DecryptOAEP(sha256.New(), nil, keys[0], wrapped, wrapLabel(header.Context, header.Recipients[0].KeyID))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	firstKey, secondKey := unwrap(firstHeader), unwrap(secondHeader)
	defer clear(firstKey)
	defer clear(secondKey)
	if len(firstKey) != 32 || len(secondKey) != 32 || bytes.Equal(firstKey, secondKey) {
		t.Fatal("recordings did not receive independent AES-256 data keys")
	}
}

func TestArchiveMissingAndWrongKeysReleaseNoPlaintext(t *testing.T) {
	keys, signers := archiveKeys(t)
	data, _ := createArchive(t, fixturePayload(), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0])
	for _, tc := range []struct {
		name       string
		trusted    []ed25519.PublicKey
		recipients []*rsa.PrivateKey
		want       error
	}{
		{"no trust roots", nil, []*rsa.PrivateKey{keys[0]}, ErrUntrustedSigner},
		{"wrong signer", []ed25519.PublicKey{signerPublic(signers[1])}, []*rsa.PrivateKey{keys[0]}, ErrUntrustedSigner},
		{"no recipient", []ed25519.PublicKey{signerPublic(signers[0])}, nil, ErrRecipientUnavailable},
		{"wrong recipient", []ed25519.PublicKey{signerPublic(signers[0])}, []*rsa.PrivateKey{keys[2]}, ErrRecipientUnavailable},
		{"nil recipient", []ed25519.PublicKey{signerPublic(signers[0])}, []*rsa.PrivateKey{nil}, ErrInvalidKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var plaintext bytes.Buffer
			if _, err := Decrypt(bytes.NewReader(data), int64(len(data)), &plaintext, tc.trusted, tc.recipients); !errors.Is(err, tc.want) {
				t.Fatal("unexpected key rejection:", err)
			}
			if plaintext.Len() != 0 {
				t.Fatal("failed key validation exposed plaintext")
			}
		})
	}
}

func TestArchiveRejectsTamperingOrderingAndTruncationBeforeDecryption(t *testing.T) {
	keys, signers := archiveKeys(t)
	data, _ := createArchive(t, fixturePayload(), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0])
	header, frames, trailer := archiveParts(t, data)
	trusted := []ed25519.PublicKey{signerPublic(signers[0])}
	reordered := append([][]byte(nil), frames...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	missing := append(append([][]byte(nil), frames[:1]...), frames[2:]...)
	duplicate := append([][]byte{frames[0]}, frames...)
	cipherFlip := bytes.Clone(data)
	cipherFlip[len(header)+frameHeaderBytes+15] ^= 1
	signatureFlip := bytes.Clone(data)
	signatureFlip[len(signatureFlip)-1] ^= 1
	headerFlip := bytes.Replace(data, []byte("session-1"), []byte("session-2"), 1)
	oversize := bytes.Clone(data)
	binary.BigEndian.PutUint32(oversize[len(header)+9:len(header)+13], ^uint32(0))
	oversizeHeader := bytes.Clone(data)
	binary.BigEndian.PutUint32(oversizeHeader[len(magic):len(magic)+4], ^uint32(0))
	oversizeTrailer := bytes.Clone(trailer)
	binary.BigEndian.PutUint32(oversizeTrailer[1:5], ^uint32(0))
	for name, invalid := range map[string][]byte{
		"ciphertext": cipherFlip, "signature": signatureFlip, "provenance": headerFlip,
		"reorder": joinArchive(header, reordered, trailer), "missing": joinArchive(header, missing, trailer),
		"duplicate": joinArchive(header, duplicate, trailer), "unfinalized": joinArchive(header, frames, nil),
		"trailing": append(bytes.Clone(data), 1), "oversize frame": oversize,
		"oversize header": oversizeHeader, "oversize manifest": joinArchive(header, frames, oversizeTrailer),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(bytes.NewReader(invalid), trusted); err == nil {
				t.Fatal("invalid archive verified")
			}
			var plaintext bytes.Buffer
			if _, err := Decrypt(bytes.NewReader(invalid), int64(len(invalid)), &plaintext, trusted, []*rsa.PrivateKey{keys[0]}); err == nil {
				t.Fatal("invalid archive decrypted")
			}
			if plaintext.Len() != 0 {
				t.Fatal("initial verification failure released plaintext")
			}
		})
	}
	for end := 0; end < len(data); end++ {
		if _, err := Verify(bytes.NewReader(data[:end]), trusted); err == nil {
			t.Fatalf("truncated prefix %d verified", end)
		}
	}
}

func TestArchiveManifestCanonicalizationAndImmutableViews(t *testing.T) {
	keys, signers := archiveKeys(t)
	_, manifest := createArchive(t, fixturePayload(), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0])
	trusted := []ed25519.PublicKey{signerPublic(signers[0])}
	canonical := manifest.CanonicalJSON()
	var indented bytes.Buffer
	if err := json.Indent(&indented, canonical, "", " "); err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(canonical, []byte(`"segments":`), []byte(`"segments":0,"segments":`), 1)
	unknown := append(bytes.Clone(canonical[:len(canonical)-1]), []byte(`,"unknown":true}`)...)
	for _, invalid := range [][]byte{indented.Bytes(), duplicate, unknown, append(bytes.Clone(canonical), ' ')} {
		// Even a genuine signature on a noncanonical encoding must be rejected.
		signature := ed25519.Sign(signers[0], append([]byte(manifestDomain), invalid...))
		if _, err := VerifyManifest(invalid, signature, trusted); err == nil {
			t.Fatal("noncanonical manifest accepted")
		}
	}
	dataCopy, signatureCopy, idsCopy := manifest.CanonicalJSON(), manifest.Signature(), manifest.RecipientKeyIDs()
	dataCopy[0] ^= 1
	signatureCopy[0] ^= 1
	idsCopy[0] = "changed"
	provenanceCopy := manifest.Provenance()
	provenanceCopy.SessionID = "changed"
	if !bytes.Equal(canonical, manifest.CanonicalJSON()) || manifest.RecipientKeyIDs()[0] == "changed" || manifest.Provenance().SessionID == "changed" {
		t.Fatal("manifest view was mutable")
	}
	if _, err := VerifyManifest(manifest.CanonicalJSON(), manifest.Signature(), trusted); err != nil {
		t.Fatal(err)
	}
}

type changingReaderAt struct {
	original, changed []byte
	passes            int
}

func (r *changingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off == 0 {
		r.passes++
	}
	source := r.original
	if r.passes > 1 {
		source = r.changed
	}
	return bytes.NewReader(source).ReadAt(p, off)
}

func TestArchiveDecryptRevalidatesMutableSource(t *testing.T) {
	keys, signers := archiveKeys(t)
	data, _ := createArchive(t, fixturePayload(), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0])
	other, _ := createArchive(t, []byte("replacement"), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0])
	corruptTrailer := bytes.Clone(data)
	corruptTrailer[len(corruptTrailer)-1] ^= 1
	for name, changed := range map[string][]byte{"header swap": other, "late trailer change": corruptTrailer, "late truncation": data[:len(data)-1]} {
		t.Run(name, func(t *testing.T) {
			var plaintext bytes.Buffer
			source := &changingReaderAt{original: data, changed: changed}
			if _, err := Decrypt(source, int64(len(data)), &plaintext, []ed25519.PublicKey{signerPublic(signers[0])}, []*rsa.PrivateKey{keys[0]}); err == nil {
				t.Fatal("source mutation accepted")
			}
			if name == "header swap" && plaintext.Len() != 0 {
				t.Fatal("changed archive header released plaintext")
			}
		})
	}
}

func TestArchiveConfigurationLimitsAndWriterFailures(t *testing.T) {
	keys, signers := archiveKeys(t)
	weak := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1)), E: 65537}
	large := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 8192), big.NewInt(1)), E: 65537}
	badExponent := &rsa.PublicKey{N: new(big.Int).Set(keys[0].N), E: 3}
	for _, public := range []*rsa.PublicKey{nil, weak, large, badExponent} {
		var dst bytes.Buffer
		if _, err := NewWriter(&dst, fixtureProvenance(), []*rsa.PublicKey{public}, signers[0], Options{}); err == nil || dst.Len() != 0 {
			t.Fatal("invalid recipient accepted or wrote header")
		}
	}
	for _, options := range []Options{{ChunkSize: -1}, {ChunkSize: MaxChunkSize + 1}, {Compression: "unrecognized"}} {
		var dst bytes.Buffer
		if _, err := NewWriter(&dst, fixtureProvenance(), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0], options); err == nil || dst.Len() != 0 {
			t.Fatal("invalid options accepted or wrote header")
		}
	}
	for _, recipients := range [][]*rsa.PublicKey{nil, {&keys[0].PublicKey, &keys[0].PublicKey}, make([]*rsa.PublicKey, MaxRecipients+1)} {
		if _, err := NewWriter(io.Discard, fixtureProvenance(), recipients, signers[0], Options{}); err == nil {
			t.Fatal("invalid recipient set accepted")
		}
	}
	if _, err := NewWriter(io.Discard, Provenance{}, []*rsa.PublicKey{&keys[0].PublicKey}, signers[0], Options{}); err == nil {
		t.Fatal("missing provenance accepted")
	}
	if _, err := NewWriter(io.Discard, fixtureProvenance(), []*rsa.PublicKey{&keys[0].PublicKey}, make(ed25519.PrivateKey, 64), Options{}); err == nil {
		t.Fatal("malformed signer accepted")
	}
	failing := &failingArchiveWriter{}
	w, err := NewWriter(failing, fixtureProvenance(), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0], Options{ChunkSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	failing.fail = true
	if _, err := w.Write([]byte("eightbyte")); err == nil {
		t.Fatal("destination failure ignored")
	}
	if err := w.Close(); err == nil {
		t.Fatal("failed writer finalized")
	}
	if _, err := w.Manifest(); err == nil {
		t.Fatal("failed writer exposed manifest")
	}
	if len(w.buffer) != 0 || w.aead != nil || len(w.signer) != 0 {
		t.Fatal("failed writer retained sensitive buffers")
	}
}

type failingArchiveWriter struct{ fail bool }

func (w *failingArchiveWriter) Write(data []byte) (int, error) {
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	return len(data), nil
}

func TestArchiveEmptyStreamAndCopiedSigner(t *testing.T) {
	keys, signers := archiveKeys(t)
	private := bytes.Clone(signers[0])
	var dst bytes.Buffer
	w, err := NewWriter(&dst, fixtureProvenance(), []*rsa.PublicKey{&keys[0].PublicKey}, private, Options{})
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(bytes.NewReader(dst.Bytes()), []ed25519.PublicKey{signerPublic(signers[0])})
	if err != nil || manifest.PlaintextBytes() != 0 || manifest.Segments() != 0 {
		t.Fatal("empty finalized stream:", err)
	}
	if !strings.Contains(string(manifest.CanonicalJSON()), `"compression":"none"`) {
		t.Fatal("default compression missing")
	}
	if manifest.CaptureOutcome() != OutcomeUnspecified {
		t.Fatal("default Close claimed a capture outcome")
	}
}

func TestArchiveCaptureOutcomeIsSignedAndInvalidFinalizationIsSticky(t *testing.T) {
	keys, signers := archiveKeys(t)
	trusted := []ed25519.PublicKey{signerPublic(signers[0])}
	for _, outcome := range []CaptureOutcome{OutcomeImported, OutcomeComplete, OutcomeInterruptedPrefix} {
		var dst bytes.Buffer
		w, err := NewWriter(&dst, fixtureProvenance(), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0], Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("captured bytes")); err != nil {
			t.Fatal(err)
		}
		if err := w.CloseWithOutcome(outcome); err != nil {
			t.Fatal(err)
		}
		if err := w.CloseWithOutcome(outcome); err != nil {
			t.Fatal("idempotent explicit finalization:", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal("deferred Close compatibility:", err)
		}
		if err := w.CloseWithOutcome(OutcomeUnspecified); !errors.Is(err, ErrClosed) {
			t.Fatal("changed finalization outcome accepted")
		}
		m, err := Verify(bytes.NewReader(dst.Bytes()), trusted)
		if err != nil || m.CaptureOutcome() != outcome {
			t.Fatal("signed outcome missing:", err)
		}
		changed := bytes.Replace(m.CanonicalJSON(), []byte(`"capture_outcome":"`+string(outcome)+`"`), []byte(`"capture_outcome":"unspecified"`), 1)
		if _, err := VerifyManifest(changed, m.Signature(), trusted); err == nil {
			t.Fatal("capture outcome was not authenticated")
		}
	}
	for _, invalid := range []CaptureOutcome{"", "unknown"} {
		var dst bytes.Buffer
		w, err := NewWriter(&dst, fixtureProvenance(), []*rsa.PublicKey{&keys[0].PublicKey}, signers[0], Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("buffered")); err != nil {
			t.Fatal(err)
		}
		before := dst.Len()
		if err := w.CloseWithOutcome(invalid); err == nil {
			t.Fatal("invalid outcome accepted")
		}
		if err := w.Close(); err == nil {
			t.Fatal("deferred Close signed after finalization error")
		}
		if dst.Len() != before {
			t.Fatal("invalid outcome flushed pending data")
		}
		if _, err := w.Manifest(); err == nil {
			t.Fatal("invalid outcome exposed manifest")
		}
	}
}
