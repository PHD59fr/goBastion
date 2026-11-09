package permissions

import "testing"

func TestValidateLegacyMetadata(t *testing.T) {
	id := identity{uid: 1000, shared: 1001, auditors: 1005}
	base := Metadata{Path: "victim/server/session.ttyrec", Dev: 1, Ino: 2, UID: 0, GID: 1001, Mode: 0660, DesiredUID: 1000, DesiredGID: 1005, DesiredMode: 0640}
	if !validOld(base, id) {
		t.Fatal("valid legacy recording rejected")
	}
	for _, mutate := range []func(*Metadata){
		func(e *Metadata) { e.UID = 1002 },
		func(e *Metadata) { e.GID = 1002 },
		func(e *Metadata) { e.Mode = 0666 },
		func(e *Metadata) { e.Mode = 04755 },
	} {
		e := base
		mutate(&e)
		if validOld(e, id) {
			t.Fatalf("unsafe legacy metadata accepted: %+v", e)
		}
	}
}

func TestBackupLocation(t *testing.T) {
	for _, path := range []string{"relative", "/run/archive/backup.json", "/run/archive", "/run/archive/../archive/b.json"} {
		if checkBackupLocation("/run/archive", path) == nil {
			t.Fatalf("accepted backup path %q", path)
		}
	}
	if err := checkBackupLocation("/run/archive", "/run/protected/backup.json"); err != nil {
		t.Fatal(err)
	}
}
