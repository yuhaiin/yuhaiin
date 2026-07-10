package node

import (
	"context"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	mg := NewManager(paths.PathGenerator.State(t.TempDir()))
	t.Cleanup(func() { _ = mg.Close() })
	return mg
}

func TestAddNode(t *testing.T) {
	mg := newTestManager(t)

	for _, item := range []contractnode.Node{
		testNode(t, "a", "feefe"),
		testNode(t, "b", "fafaf"),
		testNode(t, "c", "fazczfzf"),
		testNode(t, "d", "fazczfzf"),
	} {
		if _, err := mg.SaveContract(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}

	if err := mg.AddContractTag("test_tag", "tag", "b"); err != nil {
		t.Fatal(err)
	}
	if err := mg.AddContractTag("test_tag3", "node", "c"); err != nil {
		t.Fatal(err)
	}
	if err := mg.AddContractTag("test_tag2", "node", "b"); err != nil {
		t.Fatal(err)
	}
	if err := mg.AddContractTag("test_tag2", "node", "c"); err != nil {
		t.Fatal(err)
	}
	if err := mg.DeleteTag("test_tag2"); err != nil {
		t.Fatal(err)
	}
	if err := mg.DeleteNode("c"); err != nil {
		t.Fatal(err)
	}
}

func TestContractOnlyNodeOutbound(t *testing.T) {
	mg := newTestManager(t)
	input := testNode(t, "contract-outbound", "contract-outbound-node")
	if _, err := mg.SaveContract(context.Background(), input); err != nil {
		t.Fatalf("save contract node failed: %v", err)
	}
	if err := mg.UsePoint(input.ID); err != nil {
		t.Fatalf("use contract node failed: %v", err)
	}
	if _, err := mg.Outbound().GetDialerByID(context.Background(), input.ID); err != nil {
		t.Fatalf("get contract node dialer by id failed: %v", err)
	}
	if _, err := mg.Outbound().Get(context.Background(), "tcp", "proxy", ""); err != nil {
		t.Fatalf("get selected contract node dialer failed: %v", err)
	}
}

func TestActiveContractOnlyReturnsRuntimeDialers(t *testing.T) {
	mg := newTestManager(t)
	a := testNode(t, "active-a", "active-a-node")
	b := testNode(t, "active-b", "active-b-node")
	for _, item := range []contractnode.Node{a, b} {
		if _, err := mg.SaveContract(context.Background(), item); err != nil {
			t.Fatalf("save contract node failed: %v", err)
		}
	}

	if active := mg.ActiveContract(context.Background()); len(active) != 0 {
		t.Fatalf("active before dialer creation = %+v", active)
	}
	if _, err := mg.Outbound().GetDialerByID(context.Background(), a.ID); err != nil {
		t.Fatalf("create active-a dialer failed: %v", err)
	}
	active := mg.ActiveContract(context.Background())
	if len(active) != 1 || active[0].ID != a.ID {
		t.Fatalf("active after active-a dialer creation = %+v", active)
	}
	if _, err := mg.Outbound().GetDialerByID(context.Background(), b.ID); err != nil {
		t.Fatalf("create active-b dialer failed: %v", err)
	}
	active = mg.ActiveContract(context.Background())
	if len(active) != 2 || active[0].ID != a.ID || active[1].ID != b.ID {
		t.Fatalf("active after both dialers creation = %+v", active)
	}
	mg.store.Delete(a.ID)
	active = mg.ActiveContract(context.Background())
	if len(active) != 1 || active[0].ID != b.ID {
		t.Fatalf("active after deleting active-a = %+v", active)
	}
}

func testNode(t *testing.T, id, name string) contractnode.Node {
	t.Helper()
	protocol, err := contractnode.NewTypedProtocol(contractnode.Direct{})
	if err != nil {
		t.Fatal(err)
	}
	return contractnode.Node{
		ID:      id,
		Name:    name,
		Group:   "group",
		Origin:  "manual",
		Enabled: true,
		Chain:   []contractnode.Protocol{protocol},
	}
}
