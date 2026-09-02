package account

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

const testPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test-key"

func TestCreateDBUser_Success(t *testing.T) {
	db := newTestDB(t)
	user, err := createDBUser(db, "alice", UserCreationOptions{
		Role: models.RoleAdmin, Enabled: true, OSHOnly: true, SuperOwner: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil || user.Username != "alice" {
		t.Fatal("expected user to be created")
	}
	if user.Role != models.RoleAdmin || !user.Enabled || !user.OSHOnly || !user.SuperOwner {
		t.Fatalf("creation fields were not persisted in the insert: %+v", user)
	}
	var found models.User
	if err := db.Where("username = ?", "alice").First(&found).Error; err != nil {
		t.Fatalf("user not found in DB: %v", err)
	}
}

func TestCreateDBUser_PersistsDisabledInitialState(t *testing.T) {
	db := newTestDB(t)
	user, err := createDBUser(db, "disabled", UserCreationOptions{Role: models.RoleUser, Enabled: false})
	if err != nil {
		t.Fatalf("create disabled user: %v", err)
	}
	var found models.User
	if err := db.First(&found, "id = ?", user.ID).Error; err != nil {
		t.Fatalf("find disabled user: %v", err)
	}
	if found.Enabled {
		t.Fatal("Enabled=false was replaced by the model default")
	}
}

func TestCreateDBUser_Duplicate(t *testing.T) {
	db := newTestDB(t)
	if err := db.Exec(`CREATE UNIQUE INDEX uq_active_users_username ON users(LOWER(username)) WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("create active username index: %v", err)
	}
	options := UserCreationOptions{Role: models.RoleUser, Enabled: true}
	if _, err := createDBUser(db, "alice", options); err != nil {
		t.Fatalf("unexpected error on first create: %v", err)
	}
	user2, err := createDBUser(db, "ALICE", options)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second create error = %v, want already exists", err)
	}
	if user2 != nil {
		t.Fatal("duplicate creation must never return an existing user")
	}
	var count int64
	db.Model(&models.User{}).Where("username = ?", "alice").Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 user, got %d", count)
	}
}

func TestCreateDBUser_ConcurrentDuplicate(t *testing.T) {
	db := newTestDB(t)
	if err := db.Exec(`CREATE UNIQUE INDEX uq_active_users_username ON users(LOWER(username)) WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("create active username index: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, username := range []string{"alice", "ALICE"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, createErr := createDBUser(db, username, UserCreationOptions{Role: models.RoleUser, Enabled: true})
			errs <- createErr
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	var successes, duplicates int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case strings.Contains(err.Error(), "already exists"):
			duplicates++
		default:
			t.Fatalf("unexpected concurrent create error: %v", err)
		}
	}
	if successes != 1 || duplicates != 1 {
		t.Fatalf("successes=%d duplicates=%d, want 1 each", successes, duplicates)
	}
}

func TestCreateUser_AdapterCalled(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	// CreateUser may fail on IngressKeyFromDB (filesystem ops on /home), but
	// mock.CreateUser is called before the filesystem step, so CreatedUsers is populated.
	_ = CreateUser(db, mock, "alice", testPubKey, UserCreationOptions{Role: models.RoleUser, Enabled: true})
	found := false
	for _, u := range mock.CreatedUsers {
		if u == "alice" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected 'alice' in CreatedUsers, got %v", mock.CreatedUsers)
	}
}

func TestCreateUser_AdapterError(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	mock.ErrCreateUser = errors.New("fail")
	err := CreateUser(db, mock, "alice", testPubKey, UserCreationOptions{Role: models.RoleUser, Enabled: true})
	if err == nil {
		t.Fatal("expected error from adapter, got nil")
	}
}

func TestCreateUser_DuplicateNeverCompensatesExistingUser(t *testing.T) {
	db := newTestDB(t)
	if err := db.Exec(`CREATE UNIQUE INDEX uq_active_users_username ON users(LOWER(username)) WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("create active username index: %v", err)
	}
	existing := models.User{Username: "alice", Role: models.RoleAdmin, Enabled: true, SuperOwner: true}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("create existing user: %v", err)
	}

	mock := osadapter.NewMockAdapter()
	err := CreateUser(db, mock, "ALICE", testPubKey, UserCreationOptions{Role: models.RoleUser, Enabled: true})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("CreateUser() error = %v, want already exists", err)
	}
	if len(mock.CreatedUsers) != 0 {
		t.Fatalf("adapter called for duplicate account: %v", mock.CreatedUsers)
	}

	var found models.User
	if err := db.First(&found, "id = ?", existing.ID).Error; err != nil {
		t.Fatalf("existing user was deleted by duplicate compensation: %v", err)
	}
	if found.Role != models.RoleAdmin || !found.SuperOwner {
		t.Fatalf("existing user was modified: %+v", found)
	}
}

func TestCreateUser_CompensationPreservesPreviousSoftDeletedUser(t *testing.T) {
	db := newTestDB(t)
	if err := db.Exec(`CREATE UNIQUE INDEX uq_active_users_username ON users(LOWER(username)) WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("create active username index: %v", err)
	}
	previous := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&previous).Error; err != nil {
		t.Fatalf("create previous user: %v", err)
	}
	if err := db.Delete(&previous).Error; err != nil {
		t.Fatalf("soft-delete previous user: %v", err)
	}

	mock := osadapter.NewMockAdapter()
	mock.ErrCreateUser = errors.New("fail")
	if err := CreateUser(db, mock, "alice", testPubKey, UserCreationOptions{Role: models.RoleUser, Enabled: true}); err == nil {
		t.Fatal("expected adapter error")
	}

	var users []models.User
	if err := db.Unscoped().Where("username = ?", "alice").Find(&users).Error; err != nil {
		t.Fatalf("query users: %v", err)
	}
	if len(users) != 1 || users[0].ID != previous.ID || !users[0].DeletedAt.Valid {
		t.Fatalf("compensation changed a row it did not create: %+v", users)
	}
}

func TestCreate_MissingArgs(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	admin := newAdminUser(t, db, "admin")
	if err := Create(db, mock, admin, []string{}); err == nil {
		t.Fatal("expected missing required arguments error")
	}
}
