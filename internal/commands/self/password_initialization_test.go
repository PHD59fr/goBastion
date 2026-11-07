package self

import (
	"fmt"
	"goBastion/internal/models"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
	"gorm.io/gorm"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPasswordInitializationDoesNotReplaceExistingFactor(t *testing.T) {
	db := newTestDB(t)
	u := newRegularUser(t, db, "alice")
	u.PasswordHash = "already configured"
	if err := SetPassword(db, u, slog.Default(), nil); err == nil || !strings.Contains(err.Error(), "selfChangePassword") {
		t.Fatalf("expected change-password guidance: %v", err)
	}
}
func TestPasswordInitializationAndConcurrentChange(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprint(concurrent), func(t *testing.T) {
			db := newTestDB(t)
			u := newRegularUser(t, db, "alice")
			old, err := bcrypt.GenerateFromPassword([]byte("other-password"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			var fired atomic.Bool
			if concurrent {
				if err := db.Callback().Query().After("gorm:query").Register("concurrent:password", func(tx *gorm.DB) {
					found, ok := tx.Statement.Dest.(*models.User)
					if !ok || found.ID != u.ID || !fired.CompareAndSwap(false, true) {
						return
					}
					if err := db.Session(&gorm.Session{NewDB: true}).Model(&models.User{}).Where("id = ?", u.ID).Update("password_hash", string(old)).Error; err != nil {
						t.Error(err)
					}
				}); err != nil {
					t.Fatal(err)
				}
			}
			fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			master := os.NewFile(uintptr(fd), "pty-master")
			defer func() { _ = master.Close() }()
			if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
				t.Fatal(err)
			}
			number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
			if err != nil {
				t.Fatal(err)
			}
			slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = slave.Close() }()
			original := os.Stdin
			os.Stdin = slave
			defer func() { os.Stdin = original }()
			stop := make(chan struct{})
			defer close(stop)
			go func() {
				for range 2 {
					select {
					case <-stop:
						return
					case <-time.After(50 * time.Millisecond):
						_, _ = master.WriteString("new-password\n")
					}
				}
			}()
			err = SetPassword(db, u, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
			if (err != nil) != concurrent {
				t.Fatalf("initialization error=%v concurrent=%t", err, concurrent)
			}
			var after models.User
			if err := db.First(&after, "id = ?", u.ID).Error; err != nil {
				t.Fatal(err)
			}
			if concurrent {
				if after.PasswordHash != string(old) {
					t.Fatal("concurrent password overwritten")
				}
			} else if bcrypt.CompareHashAndPassword([]byte(after.PasswordHash), []byte("new-password")) != nil {
				t.Fatal("initial password was not saved")
			}
		})
	}
}
