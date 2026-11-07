package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func ingressFixture(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestIngressKeyRequiresSingleEntry(t *testing.T) {
	first, second := ingressFixture(t), ingressFixture(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPublic, err := ssh.NewPublicKey(&weak.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, key  string
		piv, valid bool
	}{
		{name: "normal public key file", key: first + " comment\n", valid: true},
		{name: "quoted options", key: `from="192.0.2.1,192.0.2.2",command="echo hello" ` + first, valid: true},
		{name: "two keys", key: first + "\n" + second},
		{name: "hidden after comment", key: first + " comment\r\n" + second},
		{name: "nul", key: first + "\x00"},
		{name: "weak RSA", key: string(ssh.MarshalAuthorizedKey(weakPublic))},
		{name: "attested CA", key: "cert-authority " + first, piv: true},
		{name: "ordinary CA", key: "cert-authority " + first, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseIngressKey(tc.key, tc.piv)
			if (err == nil) != tc.valid {
				t.Fatalf("accepted=%t, want %t: %v", err == nil, tc.valid, err)
			}
		})
	}
}

func TestLegacyIngressKeepsOnlyFirstKeyAndOptions(t *testing.T) {
	first := `from="192.0.2.1,192.0.2.2",command="echo hello" ` + ingressFixture(t) + " comment"
	canonical, discarded, err := CanonicalIngressKey(first+"\n"+ingressFixture(t), true)
	if err != nil || !discarded || canonical != first {
		t.Fatalf("legacy projection = %q, %t, %v", canonical, discarded, err)
	}
	if _, _, err := CanonicalIngressKey("cert-authority "+ingressFixture(t), true); err == nil {
		t.Fatal("attested CA entry accepted during sync")
	}
}
