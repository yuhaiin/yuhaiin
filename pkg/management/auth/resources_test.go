package auth

import (
	"errors"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func resourceService(t *testing.T, s *Store) (*ResourcePolicies, *ProxyCredentials) {
	t.Helper()
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	r, err := NewResourcePolicies(t.Context(), s, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r, p
}

func TestResourcePolicyAtomicPersistenceReferencesAndRestart(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	g, err := s.SaveGroup(t.Context(), principal(admin), "", GroupRequest{Name: "Finance"})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := resourceService(t, s)
	config := resource.Config{Enabled: true, Groups: []resource.GroupPolicy{{GroupID: g.ID, SharedProfile: resource.Profile{Upload: resource.Rate{BytesPerSecond: 1000}}}}}
	if _, err := r.Save(t.Context(), Principal{}, config); !errors.Is(err, ErrForbidden) {
		t.Fatal("unprivileged update", err)
	}
	if result := r.Validate(t.Context(), config); !result.Valid {
		t.Fatal(result)
	}
	saved, err := r.Save(t.Context(), principal(admin), config)
	if err != nil || saved.Revision != 1 {
		t.Fatalf("saved revision %d: %v", saved.Revision, err)
	}
	if _, err := r.Save(t.Context(), principal(admin), config); !errors.Is(err, ErrConflict) {
		t.Fatal("stale update", err)
	}
	if err := s.DeleteGroup(t.Context(), principal(admin), g.ID, g.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("dangling group reference", err)
	}
	if _, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER fail_resource_audit BEFORE INSERT ON management_security_events WHEN NEW.event='resource_policy.updated' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	saved.Enabled = false
	if _, err := r.Save(t.Context(), principal(admin), saved); err == nil {
		t.Fatal("unaudited resource update committed")
	}
	if got := r.Control.ResourceConfig(); !got.Enabled || got.Revision != 1 {
		t.Fatal("audit failure changed active policy")
	}
	var revision uint64
	if err := s.db.QueryRowContext(t.Context(), `SELECT revision FROM resource_config WHERE id=1`).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("audit failure persisted configuration: %d %v", revision, err)
	}
	if _, err := s.db.ExecContext(t.Context(), `DROP TRIGGER fail_resource_audit`); err != nil {
		t.Fatal(err)
	}
	// A second private-store reader sees the committed policy, without
	// publishing another writer over this provider's observer.
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	restarted, err := NewResourcePolicies(t.Context(), s, p)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if got := restarted.Control.ResourceConfig(); got.Revision != 1 || !got.Enabled {
		t.Fatal("restart lost resource policy")
	}
}

func TestResourceMembershipActivationPrecedesNewAuthentication(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	alice := testUser(t, s, "alice", NoManagement)
	r, p := resourceService(t, s)
	credential, err := p.Issue(t.Context(), principal(alice), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	verify := p.Verifier("entry", "http", []string{alice.ID})
	prior, err := verify(t.Context(), alice.Login, []byte(credential.Secret))
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.SaveGroup(t.Context(), principal(admin), "", GroupRequest{Name: "limited"})
	if err != nil {
		t.Fatal(err)
	}
	config := resource.Config{Enabled: true, Groups: []resource.GroupPolicy{{GroupID: group.ID, SharedProfile: resource.Profile{Upload: resource.Rate{BytesPerSecond: 1, BurstBytes: 1}}, UserLimits: resource.Limits{MaxTCPSessions: 1}}}}
	if _, err := r.Save(t.Context(), principal(admin), config); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveGroup(t.Context(), principal(admin), group.ID, GroupRequest{Name: "limited", Revision: group.Revision, Members: []string{alice.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	identity, err := verify(t.Context(), alice.Login, []byte(credential.Secret))
	if err != nil || prior.Valid() || identity == prior {
		t.Fatal("membership did not replace authenticated identity", err)
	}
	policy := r.Control.ResolveIdentity("entry", "", alice.ID, credential.ID)
	if !policy.AllowDatagram(trafficcontrol.Upload, 1) || policy.AllowDatagram(trafficcontrol.Upload, 1) {
		t.Fatal("new authentication escaped the group resource snapshot")
	}
	lease, ok := r.Control.AcquireResourceSession(alice.ID, credential.ID, false)
	if !ok {
		t.Fatal("first TCP denied")
	}
	defer lease.Release()
	if other, ok := r.Control.AcquireResourceSession(alice.ID, credential.ID, false); ok {
		other.Release()
		t.Fatal("group's per-user TCP cap escaped")
	}
}

func TestResourceConcurrentPolicyWritersHaveOneWinner(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	r, _ := resourceService(t, s)
	config := r.Control.ResourceConfig()
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _, err := r.Save(t.Context(), principal(admin), config); results <- err })
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d successful stale writes", winners)
	}
}
