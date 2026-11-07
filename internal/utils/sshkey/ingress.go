package sshkey

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ParseIngressKey accepts exactly one authorized_keys entry. Newlines inside
// the entry and additional keys must never share a fingerprint or attestation.
func ParseIngressKey(text string, pivAttested bool) (ssh.PublicKey, string, []string, error) {
	text = strings.TrimSpace(text)
	if text == "" || strings.ContainsAny(text, "\r\n\x00") {
		return nil, "", nil, fmt.Errorf("provide exactly one SSH public key on a single line")
	}
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return nil, "", nil, fmt.Errorf("invalid SSH key: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", nil, fmt.Errorf("additional SSH key data is not allowed")
	}
	if pub.Type() == ssh.KeyAlgoRSA && GetKeySize(pub) < 2048 {
		return nil, "", nil, fmt.Errorf("RSA key size must be at least 2048 bits (got %d)", GetKeySize(pub))
	}
	if pivAttested {
		for _, option := range options {
			name, _, _ := strings.Cut(option, "=")
			if strings.EqualFold(name, "cert-authority") {
				return nil, "", nil, fmt.Errorf("PIV attestation authorizes a direct key, not a certificate authority")
			}
		}
	}
	return pub, comment, options, nil
}

// CanonicalIngressKey projects legacy stored rows onto their first key. The
// first key was validated by older releases; trailing keys were not. Keep the
// valid entry usable without copying any unvalidated data to authorized_keys.
func CanonicalIngressKey(text string, pivAttested bool) (string, bool, error) {
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return "", false, err
	}
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if len(options) > 0 {
		canonical = strings.Join(options, ",") + " " + canonical
	}
	if comment != "" {
		canonical += " " + comment
	}
	if _, _, _, err := ParseIngressKey(canonical, pivAttested); err != nil {
		return "", false, err
	}
	return canonical, len(bytes.TrimSpace(rest)) > 0, nil
}
