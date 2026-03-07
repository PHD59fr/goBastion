package osadapter

import "goBastion/internal/models"

// MockAdapter is an in-memory SystemAdapter for use in tests.
// All operations are no-ops by default; callers can inject errors via the Err* fields.
type MockAdapter struct {
	// ErrCreateUser, if non-nil, is returned by CreateUser.
	ErrCreateUser error
	// ErrDeleteUser, if non-nil, is returned by DeleteUser.
	ErrDeleteUser error
	// ErrUpdateSudoers, if non-nil, is returned by UpdateSudoers.
	ErrUpdateSudoers error
	// ErrChownDir, if non-nil, is returned by ChownDir.
	ErrChownDir error
	// ErrExecCommand, if non-nil, is returned by ExecCommand.
	ErrExecCommand error
	// ExecOutput is the stdout/stderr returned by ExecCommand.
	ExecOutput string
	// HomeExists controls the result of UserHomeExists.
	HomeExists bool

	// CreatedUsers records every username passed to CreateUser.
	CreatedUsers []string
	// DeletedUsers records every username passed to DeleteUser.
	DeletedUsers []string
	// UpdatedSudoers records every user passed to UpdateSudoers.
	UpdatedSudoers []*models.User
}

// NewMockAdapter returns a MockAdapter that succeeds on every call.
func NewMockAdapter() *MockAdapter {
	return &MockAdapter{}
}

func (m *MockAdapter) CreateUser(username string) error {
	if m.ErrCreateUser != nil {
		return m.ErrCreateUser
	}
	m.CreatedUsers = append(m.CreatedUsers, username)
	return nil
}

func (m *MockAdapter) DeleteUser(username string) error {
	if m.ErrDeleteUser != nil {
		return m.ErrDeleteUser
	}
	m.DeletedUsers = append(m.DeletedUsers, username)
	return nil
}

func (m *MockAdapter) UpdateSudoers(user *models.User) error {
	if m.ErrUpdateSudoers != nil {
		return m.ErrUpdateSudoers
	}
	m.UpdatedSudoers = append(m.UpdatedSudoers, user)
	return nil
}

func (m *MockAdapter) ChownDir(_ models.User, _ string) error {
	return m.ErrChownDir
}

func (m *MockAdapter) ExecCommand(_ string, _ ...string) (string, error) {
	return m.ExecOutput, m.ErrExecCommand
}

func (m *MockAdapter) UserHomeExists(_ string) bool {
	return m.HomeExists
}
