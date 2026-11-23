package sshkey

import "testing"

func TestValidateGenerationSize(t *testing.T) {
	for _, test := range []struct {
		typeName string
		size     int
		valid    bool
	}{
		{"rsa", 2048, true}, {"rsa", 8192, true}, {"rsa", 1024, false}, {"rsa", 8193, false},
		{"ecdsa", 256, true}, {"ecdsa", 384, true}, {"ecdsa", 521, true}, {"ecdsa", 1024, false},
		{"ed25519", 256, true}, {"ed25519", 4096, false}, {"unknown", 256, false},
	} {
		if err := ValidateGenerationSize(test.typeName, test.size); (err == nil) != test.valid {
			t.Fatalf("unexpected generation size verdict for %s/%d: %v", test.typeName, test.size, err)
		}
	}
}
