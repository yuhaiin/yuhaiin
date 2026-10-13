package node

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
)

func TestSet(t *testing.T) {
	lis, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)
	defer lis.Close()

	host, port, err := net.SplitHostPort(lis.Addr().String())
	assert.NoError(t, err)
	portInt, err := strconv.Atoi(port)
	assert.NoError(t, err)

	fmt.Println(host, portInt)

	runtime := newTestRuntime(t)
	p1 := testNode(t, "a", "feefe")
	fixed, err := contractnode.NewTypedProtocol(contractnode.Fixed{
		Host: host,
		Port: int32(portInt),
	})
	assert.NoError(t, err)
	p2 := contractnode.Node{
		ID:      "b",
		Name:    "fafaf",
		Group:   "group",
		Origin:  "manual",
		Enabled: true,
		Chain:   []contractnode.Protocol{fixed},
	}
	_, err = runtime.Save(t.Context(), p1)
	assert.NoError(t, err)
	_, err = runtime.Save(t.Context(), p2)
	assert.NoError(t, err)

	se, err := NewContractSet([]string{"a", "b"}, "round_robin", runtime)
	assert.NoError(t, err)

	c, err := netapi.ParseAddress("tcp", "www.example.com")
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second*10)
	defer cancel()

	conn, err := se.Conn(ctx, c)
	assert.NoError(t, err)
	defer conn.Close()
}

type setCandidateProxy struct {
	netapi.Proxy
	laterStarted chan struct{}
	winner       bool
}

func (p setCandidateProxy) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	state := netapi.GetContext(ctx)
	if !p.winner {
		state.ConnOptions().SetBindInterface("loser-interface")
		close(p.laterStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.laterStarted:
	}
	state.ConnOptions().SetBindInterface("winner-interface")
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (setCandidateProxy) Close() error { return nil }

func TestSetPublishesTheWinningCandidateMetadata(t *testing.T) {
	runtime := newTestRuntime(t)
	first, later := testNode(t, "first", "First node"), testNode(t, "later", "Later node")
	if _, err := runtime.Save(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Save(t.Context(), later); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	runtime.proxies.store.Store(first.ID, &ProxyEntry{Name: first.Name, Proxy: setCandidateProxy{laterStarted: started, winner: true}})
	runtime.proxies.store.Store(later.ID, &ProxyEntry{Name: later.Name, Proxy: setCandidateProxy{laterStarted: started}})
	proxy, err := NewContractSet([]string{first.ID, later.ID}, "round_robin", runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	state := netapi.WithContext(ctx)
	state.SetSelector("shared", "Shared destination").SetMatchedRule("rule", "Work")
	address, err := netapi.ParseAddressPort("tcp", "example.invalid", 443)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := proxy.Conn(state, address)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if state.Hash != first.ID || state.NodeName != first.Name || state.ConnOptions().BindInterface() != "winner-interface" {
		t.Fatalf("winner metadata: %s %s %s", state.Hash, state.NodeName, state.ConnOptions().BindInterface())
	}
	selector, _ := state.Selector()
	rule, _ := state.MatchedRule()
	if selector != "shared" || rule != "rule" {
		t.Fatal("candidate overwrote routing identity")
	}
}
