package piv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCertificateFileBoundsAndRejectsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.pem")
	if err := os.WriteFile(valid, []byte("PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadCertificateFile(valid)
	if err != nil || string(data) != "PEM" {
		t.Fatalf("valid regular file rejected: %v", err)
	}
	large := filepath.Join(dir, "large.pem")
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxCertificateFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{large, link, dir, "/dev/null"} {
		if _, err := ReadCertificateFile(path); err == nil {
			t.Fatalf("unsafe certificate input accepted: %s", path)
		}
	}
}
