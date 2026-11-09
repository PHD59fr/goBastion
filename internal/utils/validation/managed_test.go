package validation

import "testing"

func TestManagedUsernameReservations(t *testing.T) {
	for _, name := range []string{"gobastion", "nobody", "gobastion-session"} {
		if IsValidManagedUsername(name) {
			t.Fatalf("reserved local account %q accepted", name)
		}
		if !IsValidUsername(name) {
			t.Fatalf("reserved name %q should remain valid for unrelated username syntax", name)
		}
	}
	if !IsValidManagedUsername("recording-test") {
		t.Fatal("ordinary managed account rejected")
	}
}
