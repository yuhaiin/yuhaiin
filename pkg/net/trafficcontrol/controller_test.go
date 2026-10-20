package trafficcontrol

import "testing"

func TestStreamScopeRetirementPreservesLiveQuota(t *testing.T) {
	parent := NewGovernor(Limits{MaxSessions: 8}, nil)
	h := newController(parent)

	firstLease, ok := h.AdmitStream("inbound-a")
	first := firstLease.scope
	if !ok {
		t.Fatal("first session was denied")
	}
	h.ForgetInbound("inbound-a")
	if h.scopes["inbound-a"] == nil {
		t.Fatal("scope with an active session was removed")
	}

	secondLease, ok := h.AdmitStream("inbound-a")
	second := secondLease.scope
	if !ok || second != first {
		t.Fatal("re-added inbound did not share its active scope")
	}
	firstLease.Release()
	if got := first.governor.Snapshot().Sessions; got != 1 {
		t.Fatalf("live scope sessions after first release = %d, want 1", got)
	}
	secondLease.Release()
	if h.scopes["inbound-a"] != nil {
		t.Fatal("retired scope remained after its final session")
	}
	if got := parent.Snapshot().Sessions; got != 0 {
		t.Fatalf("global sessions after release = %d, want 0", got)
	}

	thirdLease, ok := h.AdmitStream("inbound-a")
	third := thirdLease.scope
	if !ok || third == first {
		t.Fatal("new inbound reused a retired scope")
	}
	thirdLease.Release()
}

func TestControllerCloseRejectsNewAdmissionsAndDrainsLiveLeases(t *testing.T) {
	c := NewController()
	lease, ok := c.AdmitStream("active")
	if !ok {
		t.Fatal("initial admission")
	}
	c.Close()
	if _, ok := c.AdmitStream("new"); ok {
		t.Fatal("closed controller admitted new stream")
	}
	lease.Release()
	lease.Release()
	if s := c.Status(); s.Global.Sessions != 0 || len(s.InboundScopes) != 0 {
		t.Fatal("closed controller retained live quota", s)
	}
}

func TestQueueDiagnosticsStayBounded(t *testing.T) {
	var s Status
	for range 64 {
		if !s.AddQueue("trusted-inbound", FairStats{Bytes: 100}) {
			t.Fatal("diagnostics truncated early")
		}
	}
	if s.AddQueue("overflow", FairStats{}) || !s.Truncated || len(s.Queues) != 64 {
		t.Fatal("unbounded queue diagnostics", s)
	}
}
