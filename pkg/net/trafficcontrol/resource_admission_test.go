package trafficcontrol

import (
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

func TestResourceAdmissionSharesUserBudgetsAndReleasesOnce(t *testing.T) {
	m := NewManager()
	c := resource.Config{Enabled: true, DefaultUser: resource.Policy{Limits: resource.Limits{MaxTCPSessions: 2, MaxUDPSessions: 1, MaxSessions: 3, ConnectionsPerSecond: 0.001, ConnectionBurst: 3}}, Credentials: []resource.CredentialPolicy{{CredentialID: "phone", Policy: resource.Policy{Limits: resource.Limits{MaxTCPSessions: 1}}}}}
	bindings := []IdentityBinding{{UserID: "alice", CredentialID: "phone"}, {UserID: "alice", CredentialID: "laptop"}, {UserID: "bob", CredentialID: "bob"}}
	if err := m.ApplyResources(c, bindings); err != nil {
		t.Fatal(err)
	}
	phone, ok := m.AcquireResourceSession("alice", "phone", false)
	if !ok {
		t.Fatal("first session")
	}
	for range 100 {
		if lease, ok := m.AcquireResourceSession("alice", "phone", false); ok {
			lease.Release()
			t.Fatal("credential TCP cap bypassed")
		}
	}
	laptop, ok := m.AcquireResourceSession("alice", "laptop", false)
	if !ok {
		t.Fatal("failed credential admissions consumed user CPS")
	}
	udp, ok := m.AcquireResourceSession("alice", "laptop", true)
	if !ok {
		t.Fatal("independent UDP budget blocked")
	}
	other, ok := m.AcquireResourceSession("bob", "bob", false)
	if !ok {
		t.Fatal("another user's resources consumed")
	}
	other.Release()
	c.DefaultUser.Limits.MaxSessions = 1
	if err := m.ApplyResources(c, bindings); err != nil {
		t.Fatal(err)
	}
	if user, _, _ := m.IdentityResourceStatus("alice", "phone"); user.Total.Sessions != 3 {
		t.Fatal("update reset active reservations")
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { phone.Release(); laptop.Release(); udp.Release() })
	}
	wg.Wait()
	if user, device, _ := m.IdentityResourceStatus("alice", "phone"); user.Total.Sessions != 0 || device.Total.Sessions != 0 {
		t.Fatal("resource release leaked or underflowed")
	}
	if lease, ok := m.AcquireResourceSession("alice", "laptop", true); ok {
		lease.Release()
		t.Fatal("policy update reset the exhausted CPS budget")
	}
}

func TestRetiredIdentityCannotResetCreationBudget(t *testing.T) {
	m := NewManager()
	c := resource.Config{Enabled: true, DefaultUser: resource.Policy{Limits: resource.Limits{ConnectionsPerSecond: 0.001}}}
	bindings := []IdentityBinding{{UserID: "alice", CredentialID: "phone"}}
	if err := m.ApplyResources(c, bindings); err != nil {
		t.Fatal(err)
	}
	lease, ok := m.AcquireResourceSession("alice", "phone", false)
	if !ok {
		t.Fatal("fractional CPS must permit an initial whole event")
	}
	lease.Release()
	for range 2 {
		if err := m.ApplyResources(c, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.ApplyResources(c, bindings); err != nil {
		t.Fatal(err)
	}
	if lease, ok := m.AcquireResourceSession("alice", "phone", false); ok {
		lease.Release()
		t.Fatal("removing and re-adding an identity minted a new burst")
	}
}
