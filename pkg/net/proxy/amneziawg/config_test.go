package amneziawg

import (
	"encoding/base64"
	"strings"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func testConfig() contractnode.AmneziaWG {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return contractnode.AmneziaWG{SecretKey: key, Endpoint: []string{"10.5.0.2/24"}, Peers: []contractnode.WireguardPeer{{PublicKey: key, Endpoint: "127.0.0.1:51820", AllowedIPs: []string{"0.0.0.0/0"}}}}
}
func TestIPC(t *testing.T) {
	c := testConfig()
	c.H1 = "1000-2000"
	c.JC = 4
	c.JMin = 10
	c.JMax = 20
	c.S1 = 24
	c.I1 = "<r 64>"
	r, err := buildIPC(c)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4096)
	n, err := r.Read(data)
	if err != nil && n == 0 {
		t.Fatal(err)
	}
	txt := string(data[:n])
	for _, key := range []string{"h1=1000-2000", "jc=4", "i1=<r 64>", "allowed_ip=0.0.0.0/0"} {
		if !strings.Contains(txt, key) {
			t.Fatalf("missing %s in IPC", key)
		}
	}
}
func TestRejectUnsafeUpstreamParameters(t *testing.T) {
	for _, mutate := range []func(*contractnode.AmneziaWG){
		func(c *contractnode.AmneziaWG) { c.JC = 1; c.JMin = 600; c.JMax = 100 },
		func(c *contractnode.AmneziaWG) { c.I1 = "<r -100>" },
		func(c *contractnode.AmneziaWG) { c.H1 = "100-1" },
		func(c *contractnode.AmneziaWG) { c.MTU = 5000 },
		func(c *contractnode.AmneziaWG) { c.Peers[0].PublicKey = "bad" },
	} {
		c := testConfig()
		mutate(&c)
		if err := validateConfig(c); err == nil {
			t.Fatalf("accepted unsafe config: %+v", c)
		}
	}
}
