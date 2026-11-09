package archive

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// Verify authenticates a complete archive with trusted signing public keys. It
// never decrypts or requires a recipient private key. Returned provenance is
// trustworthy only to the extent that its signing key and recorder are trusted.
func Verify(src io.Reader, trusted []ed25519.PublicKey) (Manifest, error) {
	return scan(src, trusted, nil, nil)
}

func readHeader(src io.Reader) (headerData, [sha256.Size]byte, error) {
	var h headerData
	var prefix [len(magic) + 4]byte
	if _, err := io.ReadFull(src, prefix[:]); err != nil || string(prefix[:len(magic)]) != magic {
		return h, [sha256.Size]byte{}, ErrInvalidArchive
	}
	length := binary.BigEndian.Uint32(prefix[len(magic):])
	if length == 0 || length > maxJSONBytes {
		return h, [sha256.Size]byte{}, ErrInvalidArchive
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(src, data); err != nil {
		return h, [sha256.Size]byte{}, ErrInvalidArchive
	}
	if err := decodeCanonical(data, &h); err != nil {
		return h, [sha256.Size]byte{}, err
	}
	if err := validateHeader(h); err != nil {
		return h, [sha256.Size]byte{}, err
	}
	return h, sha256.Sum256(append(prefix[:], data...)), nil
}

func scan(src io.Reader, trusted []ed25519.PublicKey, onHeader func(headerData, [sha256.Size]byte) error, onFrame func(uint64, []byte) error) (Manifest, error) {
	if src == nil {
		return Manifest{}, ErrInvalidArchive
	}
	header, headerHash, err := readHeader(src)
	if err != nil {
		return Manifest{}, err
	}
	if _, err := trustedSigner(header.Context.SignerKeyID, trusted); err != nil {
		return Manifest{}, err
	}
	if onHeader != nil {
		if err := onHeader(header, headerHash); err != nil {
			return Manifest{}, err
		}
	}
	digest := sha256.New()
	var segments, plaintext, ciphertext uint64
	short := false
	buffer := make([]byte, header.Context.ChunkSize+gcmOverhead)
	for {
		var kind [1]byte
		if _, err := io.ReadFull(src, kind[:]); err != nil {
			return Manifest{}, ErrInvalidArchive
		}
		switch kind[0] {
		case 1:
			if short || segments >= MaxSegments {
				return Manifest{}, ErrInvalidArchive
			}
			var prefix [frameHeaderBytes]byte
			prefix[0] = 1
			if _, err := io.ReadFull(src, prefix[1:]); err != nil {
				return Manifest{}, ErrInvalidArchive
			}
			index := binary.BigEndian.Uint64(prefix[1:9])
			length := binary.BigEndian.Uint32(prefix[9:13])
			if index != segments || length <= gcmOverhead || uint64(length) > uint64(len(buffer)) {
				return Manifest{}, ErrInvalidArchive
			}
			payload := buffer[:int(length)]
			if _, err := io.ReadFull(src, payload); err != nil {
				return Manifest{}, ErrInvalidArchive
			}
			_, _ = digest.Write(prefix[:])
			_, _ = digest.Write(payload)
			if onFrame != nil {
				if err := onFrame(index, payload); err != nil {
					return Manifest{}, err
				}
			}
			segments++
			plaintext += uint64(length - gcmOverhead)
			ciphertext += uint64(frameHeaderBytes) + uint64(length)
			short = int(length)-gcmOverhead < header.Context.ChunkSize
		case 2:
			var size [4]byte
			if _, err := io.ReadFull(src, size[:]); err != nil {
				return Manifest{}, ErrInvalidArchive
			}
			length := binary.BigEndian.Uint32(size[:])
			if length == 0 || length > maxJSONBytes {
				return Manifest{}, ErrInvalidArchive
			}
			encoded := make([]byte, int(length))
			if _, err := io.ReadFull(src, encoded); err != nil {
				return Manifest{}, ErrInvalidArchive
			}
			signature := make([]byte, ed25519.SignatureSize)
			if _, err := io.ReadFull(src, signature); err != nil {
				return Manifest{}, ErrInvalidArchive
			}
			var extra [1]byte
			if _, err := io.ReadFull(src, extra[:]); err != io.EOF {
				return Manifest{}, ErrInvalidArchive
			}
			manifest, err := VerifyManifest(encoded, signature, trusted)
			if err != nil {
				return Manifest{}, err
			}
			haveContext, _ := json.Marshal(header.Context)
			wantContext, _ := json.Marshal(manifest.data.Context)
			if !bytes.Equal(haveContext, wantContext) || manifest.HeaderSHA256() != hex.EncodeToString(headerHash[:]) || manifest.CiphertextSHA256() != hex.EncodeToString(digest.Sum(nil)) || manifest.Segments() != segments || manifest.PlaintextBytes() != plaintext || manifest.CiphertextBytes() != ciphertext {
				return Manifest{}, fmt.Errorf("%w: content does not match signed manifest", ErrInvalidArchive)
			}
			return manifest, nil
		default:
			return Manifest{}, ErrInvalidArchive
		}
	}
}

// Decrypt pre-verifies the complete signed archive, then decrypts and hashes it
// again. Source must be a stable snapshot. Use a private transactional output
// and discard it on ANY error; late source mutation or I/O failure can leave an
// authenticated prefix. Invalid initial signatures never release plaintext.
func Decrypt(src io.ReaderAt, size int64, dst io.Writer, trusted []ed25519.PublicKey, recipients []*rsa.PrivateKey) (Manifest, error) {
	if src == nil || dst == nil || size < 0 {
		return Manifest{}, ErrInvalidArchive
	}
	verified, err := Verify(io.NewSectionReader(src, 0, size), trusted)
	if err != nil {
		return Manifest{}, err
	}
	if len(recipients) < 1 || len(recipients) > MaxRecipients {
		return Manifest{}, ErrRecipientUnavailable
	}
	privateKeys := make(map[string]*rsa.PrivateKey, len(recipients))
	for _, key := range recipients {
		if key == nil {
			return Manifest{}, ErrInvalidKey
		}
		id, err := RecipientKeyID(&key.PublicKey)
		if err != nil || key.Validate() != nil {
			return Manifest{}, ErrInvalidKey
		}
		privateKeys[id] = key
	}
	var aead cipher.AEAD
	var authenticatedHeader [sha256.Size]byte
	onHeader := func(header headerData, headerHash [sha256.Size]byte) error {
		if hex.EncodeToString(headerHash[:]) != verified.HeaderSHA256() {
			return fmt.Errorf("%w: source changed after verification", ErrInvalidArchive)
		}
		authenticatedHeader = headerHash
		for _, recipient := range header.Recipients {
			key := privateKeys[recipient.KeyID]
			if key == nil {
				continue
			}
			wrapped, _ := decodeBase64(recipient.WrappedKey)
			dataKey, err := rsa.DecryptOAEP(sha256.New(), nil, key, wrapped, wrapLabel(header.Context, recipient.KeyID))
			if err != nil {
				continue
			}
			if len(dataKey) != 32 {
				clear(dataKey)
				continue
			}
			block, err := aes.NewCipher(dataKey)
			clear(dataKey)
			if err != nil {
				return ErrRecipientUnavailable
			}
			aead, err = cipher.NewGCMWithRandomNonce(block)
			return err
		}
		return ErrRecipientUnavailable
	}
	onFrame := func(index uint64, payload []byte) error {
		plaintext, err := aead.Open(nil, nil, payload, frameAAD(authenticatedHeader, index, uint32(len(payload))))
		if err != nil {
			return fmt.Errorf("%w: segment authentication failed", ErrInvalidArchive)
		}
		defer clear(plaintext)
		return writeFull(dst, plaintext)
	}
	second, err := scan(io.NewSectionReader(src, 0, size), trusted, onHeader, onFrame)
	if err != nil {
		return Manifest{}, err
	}
	if !bytes.Equal(verified.canonical, second.canonical) || !bytes.Equal(verified.signature, second.signature) {
		return Manifest{}, fmt.Errorf("%w: source changed after verification", ErrInvalidArchive)
	}
	return verified, nil
}
