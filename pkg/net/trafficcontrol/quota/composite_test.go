package quota

import (
	"errors"
	"testing"
	"time"
)

func TestCredentialPlanSharesUserAndGroupReservations(t *testing.T) {
	l := newTestLedger(t, newMemoryStore())
	base := prepare(t, l, binding("user", "alice", "100"), binding("group", "finance", "70"))
	device := func(id string) *Plan {
		t.Helper()
		b := binding("credential", id, "50")
		b.OwnerUserID = "alice"
		p, err := l.PrepareCredential(t.Context(), base, []Binding{b}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	phone, laptop := device("phone"), device("laptop")
	var r Reservation
	if _, err := reserveWait(t.Context(), phone, Upload, 60, true, &r); !errors.Is(err, ErrExhausted) {
		t.Fatal("credential cap bypassed", err)
	}
	if _, err := reserveWait(t.Context(), phone, Upload, 40, true, &r); err != nil {
		t.Fatal(err)
	}
	r.Commit(40)
	if _, err := reserveWait(t.Context(), laptop, Download, 40, true, &r); !errors.Is(err, ErrExhausted) {
		t.Fatal("shared group split by credential", err)
	}
	if n, err := reserveWait(t.Context(), laptop, Download, 40, false, &r); err != nil || n != 30 {
		t.Fatalf("composite grant: %d %v", n, err)
	}
	r.Commit(30)
	if len(phone.Usage()) != 3 || len(laptop.Usage()) != 3 {
		t.Fatal("shared usage missing from composite report")
	}
	for _, usage := range base.Usage() {
		if usage.Used.Combined != "70" {
			t.Fatal("shared scope double charged or lost")
		}
	}
	if _, err := l.PrepareCredential(t.Context(), phone, nil, time.Now()); err == nil {
		t.Fatal("recursive policy chain accepted")
	}
}
