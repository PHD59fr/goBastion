package account

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils/piv"
	gosync "goBastion/internal/utils/sync"
	"golang.org/x/crypto/ssh"
)

func TestPIVInputCannotAuthorizeAnotherKey(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = t.TempDir()
	config.SetForTesting(cfg)
	type material struct {
		cert    *x509.Certificate
		private ed25519.PrivateKey
		pem     string
	}
	certificate := func(serial int64, ca bool, parent *material) material {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		x := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			x.KeyUsage |= x509.KeyUsageCertSign
		}
		issuer, signer := x, key
		if parent != nil {
			issuer, signer = parent.cert, parent.private
		}
		der, err := x509.CreateCertificate(rand.Reader, x, issuer, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return material{cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	}
	root := certificate(1, true, nil)
	intermediate := certificate(2, true, &root)
	leaf := certificate(3, false, &intermediate)
	attested, err := ssh.NewPublicKey(leaf.private.Public())
	if err != nil {
		t.Fatal(err)
	}
	extra, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extraKey, err := ssh.NewPublicKey(extra)
	if err != nil {
		t.Fatal(err)
	}
	bundle := string(ssh.MarshalAuthorizedKey(attested)) + string(ssh.MarshalAuthorizedKey(extraKey))
	if err := piv.VerifyAttestation(root.pem, intermediate.pem, leaf.pem, string(ssh.MarshalAuthorizedKey(attested))); err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
	if err := piv.VerifyAttestation(root.pem, intermediate.pem, leaf.pem, bundle); err == nil {
		t.Fatal("attestation accepted a second unverified key")
	}
	db := newTestDB(t)
	u := newRegularUser(t, db, "alice")
	for _, key := range []string{bundle, "cert-authority " + string(ssh.MarshalAuthorizedKey(attested))} {
		if err := CreateDBIngressKey(db, u, key, IngressKeyMetadata{PIVAttested: true}); err == nil {
			t.Fatal("unsafe attested entry was persisted")
		}
	}
	// Simulate a row saved by an older release and an already-published second key.
	row := models.IngressKey{UserID: u.ID, Key: bundle, Type: attested.Type(), Fingerprint: "fixture", PIVAttested: true}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Paths.HomeBaseDir, "alice", ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(bundle), 0600); err != nil {
		t.Fatal(err)
	}
	if err := gosync.New(db, osadapter.NewMockAdapter(), *slog.New(slog.NewTextHandler(io.Discard, nil))).IngressKeyFromDB(*u); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], strings.TrimSpace(string(ssh.MarshalAuthorizedKey(attested)))) || strings.Contains(string(data), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(extraKey)))) {
		t.Fatalf("unsafe authorized_keys projection: %q", data)
	}
	// A later invalid/CA entry must also remove its previously published line.
	if err := db.Model(&row).Update("key", "cert-authority "+string(ssh.MarshalAuthorizedKey(attested))).Error; err != nil {
		t.Fatal(err)
	}
	if err := gosync.New(db, osadapter.NewMockAdapter(), *slog.New(slog.NewTextHandler(io.Discard, nil))).IngressKeyFromDB(*u); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("unsafe CA key remained authorized: %q", data)
	}
}
