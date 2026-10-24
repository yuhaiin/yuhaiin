package trafficcontrol

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func slowProfile(burst int64) Profile {
	return Profile{Upload: Rate{BytesPerSecond: 1, BurstBytes: burst}}
}

func TestIdentityShapingSharedIndividualAndCredentialBudgets(t *testing.T) {
	m := NewManager()
	config := resource.Config{Enabled: true, Groups: []resource.GroupPolicy{{GroupID: "finance", SharedProfile: slowProfile(4), IndividualProfile: slowProfile(2)}, {GroupID: "staff", SharedProfile: slowProfile(10)}}, Credentials: []resource.CredentialPolicy{{CredentialID: "alice-phone", Policy: resource.Policy{Profile: slowProfile(1)}}}}
	bindings := []IdentityBinding{{UserID: "alice", CredentialID: "alice-phone", GroupIDs: []string{"staff", "finance"}}, {UserID: "alice", CredentialID: "alice-laptop", GroupIDs: []string{"finance", "staff"}}, {UserID: "bob", CredentialID: "bob", GroupIDs: []string{"finance"}}, {UserID: "carol", CredentialID: "carol"}}
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	phone := m.ResolveIdentity("", "", "alice", "alice-phone")
	laptop := m.ResolveIdentity("", "", "alice", "alice-laptop")
	bob := m.ResolveIdentity("", "", "bob", "bob")
	carol := m.ResolveIdentity("", "", "carol", "carol")
	if !phone.AllowDatagram(Upload, 1) || phone.AllowDatagram(Upload, 1) {
		t.Fatal("credential cap ignored")
	}
	if !laptop.AllowDatagram(Upload, 1) || laptop.AllowDatagram(Upload, 1) {
		t.Fatal("individual cap split per device")
	}
	if !bob.AllowDatagram(Upload, 2) || bob.AllowDatagram(Upload, 1) {
		t.Fatal("shared aggregate group cap ignored")
	}
	if !carol.AllowDatagram(Upload, 65536) {
		t.Fatal("unrelated user charged to another group")
	}
	if !phone.AllowDatagram(Download, 65536) {
		t.Fatal("independent download direction was capped")
	}
	if got := m.Usage().AdmittedUploadBytes; got != 65540 {
		t.Fatalf("multiple logical scopes double counted bytes: %d", got)
	}
}

func TestIdentityPolicyUpdatePreservesCreditsAndExistingHandles(t *testing.T) {
	m := NewManager()
	bindings := []IdentityBinding{{UserID: "alice", CredentialID: "phone", GroupIDs: []string{"group"}}}
	config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Profile: slowProfile(2)}, Groups: []resource.GroupPolicy{{GroupID: "group", SharedProfile: slowProfile(3)}}}
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	p := m.ResolveIdentity("in", "route", "alice", "phone")
	if !p.AllowDatagram(Upload, 2) {
		t.Fatal("initial burst")
	}
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	if p.AllowDatagram(Upload, 1) {
		t.Fatal("republishing minted user burst")
	}
	// An explicit override replaces the default, while shared group limits
	// remain. An old handle must observe both changes on its next operation.
	config.Users = []resource.UserPolicy{{UserID: "alice", Policy: resource.Policy{Profile: slowProfile(4)}}}
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	if p.AllowDatagram(Upload, 2) {
		t.Fatal("raising the user burst reset existing balance")
	}
	config.Enabled = false
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	if !p.AllowDatagram(Upload, 100) {
		t.Fatal("disabled resource policy still applied")
	}
}

func TestResourceSnapshotValidationAndBasePolicyComposition(t *testing.T) {
	m := NewManager()
	base := Config{Enabled: true, Global: slowProfile(3), Profiles: map[string]Profile{"route": slowProfile(2)}, RouteProfiles: map[string]string{"r": "route"}}
	if err := m.Apply(base); err != nil {
		t.Fatal(err)
	}
	config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Profile: slowProfile(10)}}
	bindings := []IdentityBinding{{UserID: "alice", CredentialID: "phone"}}
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	p := m.ResolveIdentity("in", "r", "alice", "phone")
	if !p.AllowDatagram(Upload, 2) || p.AllowDatagram(Upload, 1) {
		t.Fatal("existing route shaper bypassed")
	}
	if err := m.Apply(base); err != nil {
		t.Fatal(err)
	}
	if p.AllowDatagram(Upload, 1) {
		t.Fatal("base update reset the route or identity budget")
	}
	unknown := m.ResolveIdentity("", "", "unknown", "unknown")
	if unknown.AllowDatagram(Download, 1) || !unknown.Enabled(Download) {
		t.Fatal("unknown identity escaped managed snapshot")
	}
	if err := m.ApplyResources(config, append(bindings, bindings[0])); err == nil {
		t.Fatal("duplicate identity accepted")
	}
	if m.ResourceConfig().Enabled != true {
		t.Fatal("failed update changed active policy")
	}
}

func TestRateChangesApplyWithoutInterveningTraffic(t *testing.T) {
	m := NewManager()
	config := Config{Enabled: true, Global: slowProfile(1)}
	if err := m.Apply(config); err != nil {
		t.Fatal(err)
	}
	p := m.Resolve("", "")
	if !p.AllowDatagram(Upload, 1) {
		t.Fatal("initial burst")
	}
	for _, rate := range []int64{2, 3, 1} {
		config.Global.Upload.BytesPerSecond = rate
		if err := m.Apply(config); err != nil {
			t.Fatal(err)
		}
		limiter := m.active.Load().global.up
		limiter.mu.Lock()
		got := limiter.rate
		limiter.mu.Unlock()
		if got != rate {
			t.Fatalf("rate %d not activated without traffic: %d", rate, got)
		}
	}
	if p.AllowDatagram(Upload, 1) {
		t.Fatal("intermediate updates minted a new burst")
	}
}

func TestDevicesShareCompiledUserStateAndKeepTheirOwnScopes(t *testing.T) {
	l := quota.New(initialQuotaStore{})
	defer l.Close(context.Background())
	m := NewManagerWithQuotas(l)
	config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Quotas: []resource.Quota{{ID: "daily", Period: "daily", Combined: "100", Action: "warn"}}}, Groups: []resource.GroupPolicy{{GroupID: "team", SharedProfile: slowProfile(10)}}}
	bindings := []IdentityBinding{{UserID: "alice", CredentialID: "phone", GroupIDs: []string{"team"}}, {UserID: "alice", CredentialID: "laptop", GroupIDs: []string{"team"}}}
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	r := m.active.Load().resources
	a, b := identityKey{"alice", "phone"}, identityKey{"alice", "laptop"}
	if r.quotaPlans[a] != r.quotaPlans[b] || &r.identities[a].up[0] != &r.identities[b].up[0] || &r.bindings[0].GroupIDs[0] != &r.bindings[1].GroupIDs[0] {
		t.Fatal("device count duplicated user/group state")
	}
}

func TestAuthenticatedPacketResolutionIsAllocationFreeAndRejectsMissingIDs(t *testing.T) {
	m := NewManager()
	config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Profile: Profile{Upload: Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 30}}}}
	if err := m.ApplyResources(config, []IdentityBinding{{UserID: "alice", CredentialID: "phone"}}); err != nil {
		t.Fatal(err)
	}
	identity := &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}
	if allocations := testing.AllocsPerRun(1000, func() {
		p := ResolveAuthenticatedPolicy(m, "entry", "", identity)
		if !p.AllowDatagram(Upload, 1350) {
			panic("unexpected drop")
		}
	}); allocations != 0 {
		t.Fatalf("packet resolution allocated: %g", allocations)
	}
	malformed := m.ResolveAuthenticated("entry", "", &proxyauth.Identity{Context: t.Context()})
	if malformed.AllowDatagram(Upload, 1) {
		t.Fatal("missing authenticated IDs escaped the resource snapshot")
	}
}

func TestResourceConcurrentUpdatesAndMembershipOrder(t *testing.T) {
	m := NewManager()
	config := resource.Config{Enabled: true, Groups: []resource.GroupPolicy{{GroupID: "a", SharedProfile: Profile{Upload: Rate{BytesPerSecond: 1 << 40}}}, {GroupID: "b", SharedProfile: Profile{Upload: Rate{BytesPerSecond: 1 << 40}}}}}
	bindings := make([]IdentityBinding, 1024)
	for i := range bindings {
		bindings[i] = IdentityBinding{UserID: fmt.Sprint(i), CredentialID: fmt.Sprint(i), GroupIDs: []string{"b", "a"}}
	}
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		p := m.ResolveIdentity("", "", fmt.Sprint(i), fmt.Sprint(i))
		wg.Go(func() {
			for range 2000 {
				p.AllowDatagram(Upload, 1)
			}
		})
	}
	wg.Go(func() {
		for range 20 {
			if err := m.ApplyResources(config, bindings); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	if got := m.Usage().AdmittedUploadBytes; got != 16000 {
		t.Fatalf("unexpected accepted accounting %d", got)
	}
}

func BenchmarkIdentityDatagramPolicy(b *testing.B) {
	for _, groups := range []int{0, 4, 64} {
		b.Run(fmt.Sprint(groups), func(b *testing.B) {
			m := NewManager()
			profile := Profile{Upload: Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 30}}
			config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Profile: profile}}
			binding := IdentityBinding{UserID: "alice", CredentialID: "phone"}
			for i := range groups {
				id := fmt.Sprint(i)
				config.Groups = append(config.Groups, resource.GroupPolicy{GroupID: id, SharedProfile: profile})
				binding.GroupIDs = append(binding.GroupIDs, id)
			}
			if err := m.ApplyResources(config, []IdentityBinding{binding}); err != nil {
				b.Fatal(err)
			}
			p := m.ResolveIdentity("", "", "alice", "phone")
			b.ReportAllocs()
			for b.Loop() {
				if !p.AllowDatagram(Upload, 1350) {
					b.Fatal("unexpected drop")
				}
			}
		})
	}
}
