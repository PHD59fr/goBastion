// Package permissions performs an explicit offline migration of one legacy
// recording account. It changes metadata only and never opens recording data.
package permissions

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"goBastion/internal/recording"
	"golang.org/x/sys/unix"
)

const Version = 1
const MaxEntries = 100000
const maxBackupBytes = 32 << 20

type Metadata struct {
	Path        string `json:"path"`
	Dev         uint64 `json:"dev"`
	Ino         uint64 `json:"ino"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Mode        uint32 `json:"mode"`
	DesiredUID  uint32 `json:"desired_uid"`
	DesiredGID  uint32 `json:"desired_gid"`
	DesiredMode uint32 `json:"desired_mode"`
}

type PlanData struct {
	Version int        `json:"version"`
	Archive string     `json:"archive"`
	User    string     `json:"user"`
	Retired bool       `json:"retired"`
	RootDev uint64     `json:"root_dev"`
	RootIno uint64     `json:"root_ino"`
	Entries []Metadata `json:"entries"`
}

type identity struct {
	uid, shared, auditors uint32
	retired               bool
	managed               map[uint32]string
}

func openAbsoluteDir(path string, trustedParent bool) (int, error) {
	if !filepath.IsAbs(path) || path != filepath.Clean(path) || path == "/" {
		return -1, errors.New("invalid absolute directory path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err = recording.ValidateNoACL(fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for n, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		if e = recording.ValidateNoACL(fd); e != nil {
			_ = unix.Close(fd)
			return -1, e
		}
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			_ = unix.Close(fd)
			return -1, e
		}
		if n < len(parts)-1 && (st.Uid != 0 || st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0) {
			_ = unix.Close(fd)
			return -1, errors.New("untrusted path ancestor")
		}
		if trustedParent && n == len(parts)-1 && (st.Uid != 0 || st.Mode&0022 != 0) {
			_ = unix.Close(fd)
			return -1, errors.New("backup parent must be root-owned and not writable by other users")
		}
	}
	return fd, nil
}

func stat(fd int) (unix.Stat_t, error) { var s unix.Stat_t; err := unix.Fstat(fd, &s); return s, err }

func openChild(parent int, name string, directory bool) (int, unix.Stat_t, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return -1, unix.Stat_t{}, errors.New("invalid path component")
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(parent, name, flags, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	if err = recording.ValidateNoACL(fd); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	s, err := stat(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, s, err
	}
	want := uint32(unix.S_IFREG)
	if directory {
		want = unix.S_IFDIR
	}
	if s.Mode&unix.S_IFMT != want || !directory && s.Nlink != 1 {
		_ = unix.Close(fd)
		return -1, s, errors.New("unsafe recording inode")
	}
	var named unix.Stat_t
	if err = unix.Fstatat(parent, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || named.Dev != s.Dev || named.Ino != s.Ino {
		_ = unix.Close(fd)
		return -1, s, errors.New("recording namespace changed")
	}
	return fd, s, nil
}

func names(fd int) ([]string, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "recording-inventory")
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(MaxEntries + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > MaxEntries {
		return nil, errors.New("recording inventory limit reached")
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Name())
	}
	return result, nil
}

func entry(path string, s unix.Stat_t, uid, gid, mode uint32) Metadata {
	return Metadata{path, uint64(s.Dev), s.Ino, s.Uid, s.Gid, s.Mode & 07777, uid, gid, mode}
}

func validOld(e Metadata, id identity) bool {
	if e.Path == "." {
		return e.UID == 0 && e.GID == id.shared && (e.Mode == 03770 || e.Mode == 0751)
	}
	if e.UID != 0 && e.UID != id.uid {
		return false
	}
	if e.GID != id.shared && e.GID != id.auditors {
		return false
	}
	if e.Mode&0002 != 0 {
		return false
	}
	if e.DesiredMode == 02750 {
		return e.Mode == 0700 || e.Mode == 0750 || e.Mode == 0770 || e.Mode == 02750 || e.Mode == 02770 || e.Mode == 03770
	}
	return e.Mode == 0600 || e.Mode == 0640 || e.Mode == 0660 || e.Mode == 0644
}

func noteOldUID(id *identity, uid uint32) error {
	if !id.retired || uid == 0 {
		return nil
	}
	if uid < 1000 || uid >= 65000 || id.uid != 0 && id.uid != uid {
		return errors.New("mixed or invalid prior recording owner")
	}
	id.uid = uid
	return nil
}

func appendEntry(p *PlanData, e Metadata, id *identity) error {
	if len(p.Entries) >= MaxEntries {
		return errors.New("recording inventory limit reached")
	}
	if err := noteOldUID(id, e.UID); err != nil {
		return err
	}
	if !validOld(e, *id) {
		return fmt.Errorf("unsafe legacy metadata: %s", e.Path)
	}
	p.Entries = append(p.Entries, e)
	return nil
}

// Plan inventories only the named account and the shared root. Hidden private
// spools are validated and left untouched; unexpected namespace entries fail.
func Plan(archive, account string, retired ...bool) (PlanData, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return PlanData{}, errors.New("root required")
	}
	isRetired := len(retired) > 0 && retired[0]
	id, err := identities(account, isRetired)
	if err != nil {
		return PlanData{}, err
	}
	root, err := openAbsoluteDir(archive, false)
	if err != nil {
		return PlanData{}, err
	}
	defer func() { _ = unix.Close(root) }()
	rs, err := stat(root)
	if err != nil {
		return PlanData{}, err
	}
	p := PlanData{Version: Version, Archive: archive, User: account, Retired: isRetired, RootDev: uint64(rs.Dev), RootIno: rs.Ino}
	if err = appendEntry(&p, entry(".", rs, 0, id.shared, 0751), &id); err != nil {
		return PlanData{}, err
	}
	accountFD, as, err := openChild(root, account, true)
	if err != nil {
		return PlanData{}, err
	}
	defer func() { _ = unix.Close(accountFD) }()
	if as.Dev != rs.Dev {
		return PlanData{}, errors.New("cross-device recording account")
	}
	if err = appendEntry(&p, entry(account, as, desiredUID(id), id.auditors, 02750), &id); err != nil {
		return PlanData{}, err
	}
	serverNames, err := names(accountFD)
	if err != nil {
		return PlanData{}, err
	}
	for _, server := range serverNames {
		if strings.HasPrefix(server, ".") {
			return PlanData{}, errors.New("unexpected hidden account entry")
		}
		serverFD, ss, e := openChild(accountFD, server, true)
		if e != nil {
			return PlanData{}, e
		}
		if ss.Dev != rs.Dev {
			_ = unix.Close(serverFD)
			return PlanData{}, errors.New("cross-device recording server")
		}
		e = appendEntry(&p, entry(account+"/"+server, ss, desiredUID(id), id.auditors, 02750), &id)
		if e == nil {
			e = inventoryServer(&p, &id, serverFD, account+"/"+server, rs.Dev)
		}
		_ = unix.Close(serverFD)
		if e != nil {
			return PlanData{}, e
		}
	}
	if id.retired && id.uid != 0 {
		if _, assigned := id.managed[id.uid]; assigned {
			return PlanData{}, errors.New("prior recording UID is now assigned to another account")
		}
	}
	return p, nil
}

func desiredUID(id identity) uint32 {
	if id.retired {
		return 0
	}
	return id.uid
}

func inventoryServer(p *PlanData, id *identity, serverFD int, prefix string, dev uint64) error {
	fileNames, err := names(serverFD)
	if err != nil {
		return err
	}
	for _, name := range fileNames {
		if strings.HasPrefix(name, ".") {
			if !strings.HasPrefix(name, ".ssh-record-") && !strings.HasPrefix(name, ".publish-") {
				return errors.New("unexpected hidden recording entry")
			}
			fd, s, err := openChild(serverFD, name, true)
			if err != nil {
				return err
			}
			if err := noteOldUID(id, s.Uid); err != nil {
				_ = unix.Close(fd)
				return err
			}
			if uint64(s.Dev) != dev || s.Uid != id.uid && s.Uid != 0 || s.Mode&07777 != 0700 && s.Mode&07777 != 02700 {
				_ = unix.Close(fd)
				return errors.New("unsafe private recording spool")
			}
			if len(p.Entries) >= MaxEntries {
				_ = unix.Close(fd)
				return errors.New("recording inventory limit reached")
			}
			p.Entries = append(p.Entries, entry(prefix+"/"+name, s, s.Uid, s.Gid, s.Mode&07777))
			err = inventorySpool(p, id, fd, prefix+"/"+name, dev)
			_ = unix.Close(fd)
			if err != nil {
				return err
			}
			continue
		}
		if !strings.HasSuffix(name, ".ttyrec") && !strings.HasSuffix(name, ".ttyrec.gz") {
			return errors.New("unexpected recording file")
		}
		fd, s, err := openChild(serverFD, name, false)
		if err != nil {
			return err
		}
		_ = unix.Close(fd)
		if uint64(s.Dev) != dev {
			return errors.New("cross-device recording file")
		}
		if err = appendEntry(p, entry(prefix+"/"+name, s, desiredUID(*id), id.auditors, 0640), id); err != nil {
			return err
		}
	}
	return nil
}

func inventorySpool(p *PlanData, id *identity, fd int, prefix string, dev uint64) error {
	entries, err := names(fd)
	if err != nil {
		return err
	}
	if id.retired && len(entries) != 0 {
		return errors.New("retired recording account has pending private spool content")
	}
	for _, name := range entries {
		child, s, err := openChild(fd, name, false)
		if err != nil {
			return err
		}
		_ = unix.Close(child)
		if err = noteOldUID(id, s.Uid); err != nil {
			return err
		}
		if uint64(s.Dev) != dev || s.Uid != id.uid && s.Uid != 0 || s.Mode&07777 != 0600 {
			return errors.New("unsafe private spool file")
		}
		if len(p.Entries) >= MaxEntries {
			return errors.New("recording inventory limit reached")
		}
		p.Entries = append(p.Entries, entry(prefix+"/"+name, s, s.Uid, s.Gid, 0600))
	}
	return nil
}

func Encode(p PlanData) ([]byte, error) { return json.MarshalIndent(p, "", "  ") }
