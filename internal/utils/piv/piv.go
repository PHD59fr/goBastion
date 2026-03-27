// Package piv provides helpers for Yubico PIV key attestation verification.
//
// PIV attestation allows users to prove that their SSH private key was
// generated inside a hardware token (e.g. YubiKey) and cannot be exported.
//
// The chain is:
//
//	attestationCert (device-specific, signed by intermediary)
//	-> intermediateCert (signed by Yubico PIV CA)
//	-> trustAnchorCert (Yubico root CA, stored in DB by admin)
//
// The attestation cert also embeds the public key that matches the SSH key
// the user wants to add. We verify that they match.
package piv

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// VerifyAttestation verifies a Yubico PIV attestation chain and checks that
// the public key inside attestCertPEM matches sshPubKeyText.
//
//   - anchorPEM: PEM-encoded trust anchor certificate (stored in DB)
//   - intermediatePEM: PEM-encoded intermediate certificate provided by the user
//   - attestCertPEM: PEM-encoded attestation certificate provided by the user
//   - sshPubKeyText: the authorized_keys-format SSH public key to be added
//
// Returns nil if the chain is valid and the public key matches.
func VerifyAttestation(anchorPEM, intermediatePEM, attestCertPEM, sshPubKeyText string) error {
	anchor, err := parseCert(anchorPEM)
	if err != nil {
		return fmt.Errorf("parsing trust anchor: %w", err)
	}
	intermediate, err := parseCert(intermediatePEM)
	if err != nil {
		return fmt.Errorf("parsing intermediate: %w", err)
	}
	attest, err := parseCert(attestCertPEM)
	if err != nil {
		return fmt.Errorf("parsing attestation cert: %w", err)
	}

	// Build a certificate pool from the anchor (root) and intermediate.
	roots := x509.NewCertPool()
	roots.AddCert(anchor)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// PIV attestation certs don't have a standard EKU - skip that check.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := attest.Verify(opts); err != nil {
		return fmt.Errorf("attestation chain verification failed: %w", err)
	}

	// Verify that the public key in the attestation cert matches the SSH key.
	sshKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPubKeyText))
	if err != nil {
		return fmt.Errorf("parsing SSH public key: %w", err)
	}

	cryptoKey, ok := sshKey.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("SSH key does not expose a crypto.PublicKey")
	}

	if err := publicKeyMatch(attest.PublicKey, cryptoKey.CryptoPublicKey()); err != nil {
		return fmt.Errorf("SSH key does not match attestation certificate: %w", err)
	}

	return nil
}

// parseCert decodes the first PEM block and parses it as a DER certificate.
func parseCert(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// publicKeyMatch compares two crypto.PublicKey values by their serialized form.
func publicKeyMatch(certKey, sshKey interface{}) error {
	certDER, err := marshalPublicKey(certKey)
	if err != nil {
		return fmt.Errorf("marshaling cert key: %w", err)
	}
	sshDER, err := marshalPublicKey(sshKey)
	if err != nil {
		return fmt.Errorf("marshaling SSH key: %w", err)
	}
	if string(certDER) != string(sshDER) {
		return fmt.Errorf("keys differ")
	}
	return nil
}

func marshalPublicKey(pub interface{}) ([]byte, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return x509.MarshalPKIXPublicKey(k)
	case *ecdsa.PublicKey:
		return x509.MarshalPKIXPublicKey(k)
	default:
		return x509.MarshalPKIXPublicKey(pub)
	}
}
