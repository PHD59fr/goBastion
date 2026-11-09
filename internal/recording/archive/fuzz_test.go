package archive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func FuzzVerifyArchive(f *testing.F) {
	recipient, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		f.Fatal("generate ephemeral recipient key:", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal("generate ephemeral signing key:", err)
	}
	var seedArchive bytes.Buffer
	writer, err := NewWriter(&seedArchive, fixtureProvenance(), []*rsa.PublicKey{&recipient.PublicKey}, private, Options{Compression: "none"})
	if err != nil {
		f.Fatal("create valid fuzz seed:", err)
	}
	if _, err := writer.Write([]byte("bounded archive parser seed")); err != nil {
		f.Fatal("write fuzz seed:", err)
	}
	if err := writer.Close(); err != nil {
		f.Fatal("finalize fuzz seed:", err)
	}
	trustedPrefix := bytes.Clone(public)
	seed := append(bytes.Clone(trustedPrefix), seedArchive.Bytes()...)
	f.Add(seed)
	f.Add(bytes.Clone(trustedPrefix))
	f.Add(append(bytes.Clone(trustedPrefix), []byte("not an archive")...))
	f.Add(append(bytes.Clone(trustedPrefix), seedArchive.Bytes()[:len(seedArchive.Bytes())/2]...))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) < ed25519.PublicKeySize || len(input)-ed25519.PublicKeySize > 1<<20 {
			return
		}
		trusted := []ed25519.PublicKey{ed25519.PublicKey(input[:ed25519.PublicKeySize])}
		data := input[ed25519.PublicKeySize:]
		manifest, verifyErr := Verify(bytes.NewReader(data), trusted)
		if verifyErr != nil {
			return
		}
		canonical := manifest.CanonicalJSON()
		signature := manifest.Signature()
		if _, err := VerifyManifest(canonical, signature, trusted); err != nil {
			t.Fatalf("archive accepted but its manifest did not: %v", err)
		}
		flipped := bytes.Clone(signature)
		if len(flipped) == 0 {
			t.Fatal("accepted manifest has an empty signature")
		}
		flipped[0] ^= 1
		if _, err := VerifyManifest(canonical, flipped, trusted); err == nil {
			t.Fatal("manifest accepted after signature bit flip")
		}
		trailing := append(bytes.Clone(data), 0)
		if _, err := Verify(bytes.NewReader(trailing), trusted); err == nil {
			t.Fatal("archive accepted with trailing byte")
		}
	})
}
