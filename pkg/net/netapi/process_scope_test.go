package netapi

import "testing"

type testProcessScope struct{}

func (*testProcessScope) ProcessName(string, Address, Address) (Process, error) {
	return Process{}, nil
}

func TestProcessScopeFollowsForkAndClears(t *testing.T) {
	scope := &testProcessScope{}
	parent := WithContext(t.Context()).SetProcessScope(scope)
	if child := ForkContext(parent); child.ProcessScope() != scope {
		t.Fatal("dial attempt lost the flow's namespace")
	}
	// A reused context must not keep the previous flow's namespace.
	if parent.SetProcessScope(nil).ProcessScope() != nil {
		t.Fatal("nil scope did not clear the namespace")
	}
	if WithContext(t.Context()).ProcessScope() != nil {
		t.Fatal("new context has a namespace")
	}
}
