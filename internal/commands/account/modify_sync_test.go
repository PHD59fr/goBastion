package account

import (
	"errors"
	"goBastion/internal/models"
	"testing"
)

func TestModifyReconcilesCommittedRoleAndPropagatesFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failed helper"}[fail], func(t *testing.T) {
			db := newTestDB(t)
			admin := newAdminUser(t, db, "admin")
			target := newRegularUser(t, db, "alice")
			prior := syncModifiedAccount
			t.Cleanup(func() { syncModifiedAccount = prior })
			sentinel := errors.New("reconciliation refused")
			calls := 0
			syncModifiedAccount = func(name string) error {
				calls++
				if name != target.Username {
					t.Fatalf("unexpected target %s", name)
				}
				var fresh models.User
				if err := db.First(&fresh, "id = ?", target.ID).Error; err != nil {
					t.Fatal(err)
				}
				if !fresh.IsAdmin() {
					t.Fatal("helper called before policy committed")
				}
				if fail {
					return sentinel
				}
				return nil
			}
			err := Modify(db, admin, []string{"--user", "alice", "--sysrole", "admin"})
			if fail && !errors.Is(err, sentinel) {
				t.Fatalf("lost reconciliation error: %v", err)
			}
			if !fail && err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("reconciliation called %d times", calls)
			}
		})
	}
}

func TestExpireReconcilesDisabledPolicyAndReturnsFailure(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	target := newRegularUser(t, db, "alice")
	prior := syncModifiedAccount
	t.Cleanup(func() { syncModifiedAccount = prior })
	refused := errors.New("revocation helper failed")
	syncModifiedAccount = func(name string) error {
		var fresh models.User
		if err := db.First(&fresh, "id = ?", target.ID).Error; err != nil {
			t.Fatal(err)
		}
		if name != target.Username || fresh.Enabled {
			t.Fatal("revocation did not follow committed disabled state")
		}
		return refused
	}
	if err := Expire(db, admin, []string{"--user", "alice"}); !errors.Is(err, refused) {
		t.Fatalf("lost failed revocation: %v", err)
	}
}

func TestUnexpireReconcilesAfterEnabling(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	target := newRegularUser(t, db, "alice")
	if err := db.Model(target).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	prior := syncModifiedAccount
	t.Cleanup(func() { syncModifiedAccount = prior })
	calls := 0
	syncModifiedAccount = func(name string) error {
		calls++
		var fresh models.User
		if err := db.First(&fresh, "id = ?", target.ID).Error; err != nil {
			t.Fatal(err)
		}
		if name != target.Username || !fresh.Enabled {
			t.Fatal("helper ran before committed enable")
		}
		return nil
	}
	if err := Unexpire(db, admin, []string{"--user", "alice"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("helper calls %d", calls)
	}
}
