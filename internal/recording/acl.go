package recording

import (
	"fmt"
	"golang.org/x/sys/unix"
)

// ValidateNoACL rejects ACL policies that Unix owner/group/mode validation does
// not describe. Unsupported ACL namespaces imply no ACL feature on that FS;
// permission/I/O errors never imply absence. Qualified storage is POSIX Linux.
func ValidateNoACL(fd int) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default", "system.nfs4_acl", "system.richacl"} {
		size, err := unix.Fgetxattr(fd, name, nil)
		if err == unix.ENODATA || err == unix.ENOTSUP {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot verify recording ACL policy: %w", err)
		}
		if size != 0 {
			return fmt.Errorf("extended recording ACL requires explicit offline repair")
		}
	}
	return nil
}
