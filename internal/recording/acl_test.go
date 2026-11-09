package recording

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"testing"
)

func TestArchiveRejectsExtendedACL(t *testing.T) {
	for _, attr := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		t.Run(attr, func(t *testing.T) {
			dir := privateTestArchive(t)
			f, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			raw := make([]byte, 4)
			binary.LittleEndian.PutUint32(raw, 2)
			for _, entry := range []struct {
				tag, perm uint16
				id        uint32
			}{{1, 7, ^uint32(0)}, {2, 5, 1002}, {4, 5, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}} {
				field := make([]byte, 8)
				binary.LittleEndian.PutUint16(field, entry.tag)
				binary.LittleEndian.PutUint16(field[2:], entry.perm)
				binary.LittleEndian.PutUint32(field[4:], entry.id)
				raw = append(raw, field...)
			}
			if err = unix.Fsetxattr(int(f.Fd()), attr, raw, 0); err == unix.ENOTSUP {
				t.Skip("filesystem does not support POSIX ACL")
			} else if err != nil {
				t.Fatal(err)
			}
			if _, err = openArchiveDirectory(dir, ".", os.Geteuid()); err == nil || !strings.Contains(err.Error(), "ACL") {
				t.Fatalf("extended ACL accepted or wrong guard: %v", err)
			}
		})
	}
}
