package session

import (
	"path/filepath"
	"sync"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestConcurrentSQLiteSessionAdmissionRespectsInstanceLimit(t *testing.T) {
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Session.MaxConcurrentSessions = 1
	config.SetForTesting(cfg)

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "sessions.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(4)
	if err := db.AutoMigrate(&models.ActiveSession{}); err != nil {
		t.Fatal(err)
	}
	actor := createAdmissionActor(t, db)

	start := make(chan struct{})
	type outcome struct {
		release func()
		err     error
	}
	results := make(chan outcome, 4)
	var workers sync.WaitGroup
	for _, id := range []string{"one", "two", "three", "four"} {
		workers.Add(1)
		go func(id string) {
			defer workers.Done()
			<-start
			release, err := registerActiveSession(db, actor, id, "ssh")
			results <- outcome{release: release, err: err}
		}(id)
	}
	close(start)
	workers.Wait()
	close(results)
	admitted := 0
	for result := range results {
		if result.err == nil {
			admitted++
			t.Cleanup(result.release)
		}
	}
	var count int64
	if err := db.Model(&models.ActiveSession{}).Where("instance_id = ?", config.InstanceID()).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if admitted > 1 || count != int64(admitted) {
		t.Fatalf("concurrent admission exceeded the instance limit: admitted=%d, registered=%d", admitted, count)
	}
	// SQLite can fail all read-to-write upgrades under simultaneous contention.
	// Once contenders have stopped, admission must recover and keep enforcing
	// the ceiling; a test where every admission always fails must not pass.
	if admitted == 0 {
		release, err := registerActiveSession(db, actor, "after-contention", "ssh")
		if err != nil {
			t.Fatalf("admission did not recover after contention: %v", err)
		}
		t.Cleanup(release)
	}
	if release, err := registerActiveSession(db, actor, "over-limit", "ssh"); err == nil {
		release()
		t.Fatal("admitted another session while the recovered slot was occupied")
	}

}
