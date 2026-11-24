package inbound

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSSHHostLoopbackValidate(t *testing.T) {
	m := func(protocol, session string, sport uint16, host string, hport uint16) SSHHostLoopbackMapping {
		return SSHHostLoopbackMapping{Protocol: protocol, SessionAddress: session, SessionPort: sport, HostAddress: host, HostPort: hport}
	}
	good := SSHHostLoopback{Enabled: true, Mappings: []SSHHostLoopbackMapping{
		m("tcp", "127.0.0.1", 5432, "127.0.0.1", 5432),
		m("tcp", "::1", 5432, "::1", 5432),
		m("tcp", "::1", 8080, "127.0.0.1", 18080),
		m("udp", "127.0.0.1", 5432, "127.0.0.53", 53),
		m("udp", "127.0.0.1", 1, "::1", 65535),
	}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := good.Mappings[2].Session().String(); got != "[::1]:8080" {
		t.Fatalf("Session() = %s", got)
	}
	if got := good.Mappings[2].Host().String(); got != "127.0.0.1:18080" {
		t.Fatalf("Host() = %s", got)
	}
	for name, tc := range map[string]struct {
		mapping SSHHostLoopbackMapping
		message string
	}{
		"protocol":            {m("icmp", "127.0.0.1", 1, "127.0.0.1", 1), "tcp or udp"},
		"uppercase protocol":  {m("TCP", "127.0.0.1", 1, "127.0.0.1", 1), "tcp or udp"},
		"localhost name":      {m("tcp", "localhost", 1, "127.0.0.1", 1), "session address"},
		"session 127.0.0.2":   {m("tcp", "127.0.0.2", 1, "127.0.0.1", 1), "session address"},
		"session unspecified": {m("tcp", "0.0.0.0", 1, "127.0.0.1", 1), "session address"},
		"session ::":          {m("tcp", "::", 1, "127.0.0.1", 1), "session address"},
		"host unspecified":    {m("tcp", "127.0.0.1", 1, "0.0.0.0", 1), "host address"},
		"host ::":             {m("tcp", "127.0.0.1", 1, "::", 1), "host address"},
		"host lan":            {m("tcp", "127.0.0.1", 1, "192.168.1.10", 1), "host address"},
		"host public":         {m("tcp", "127.0.0.1", 1, "8.8.8.8", 1), "host address"},
		"host mapped":         {m("tcp", "127.0.0.1", 1, "::ffff:127.0.0.1", 1), "host address"},
		"host zone":           {m("tcp", "127.0.0.1", 1, "::1%lo", 1), "host address"},
		"host garbage":        {m("tcp", "127.0.0.1", 1, "not-an-ip", 1), "host address"},
		"session port 0":      {m("tcp", "127.0.0.1", 0, "127.0.0.1", 1), "1-65535"},
		"host port 0":         {m("tcp", "127.0.0.1", 1, "127.0.0.1", 0), "1-65535"},
	} {
		h := SSHHostLoopback{Enabled: true, Mappings: []SSHHostLoopbackMapping{good.Mappings[0], tc.mapping}}
		err := h.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.message) || !strings.Contains(err.Error(), "mapping 2") {
			t.Errorf("%s: %v", name, err)
		}
		// Invalid mappings are rejected while disabled too.
		h.Enabled = false
		if h.Validate() == nil {
			t.Errorf("%s: accepted while disabled", name)
		}
	}
	dup := SSHHostLoopback{Mappings: []SSHHostLoopbackMapping{m("tcp", "127.0.0.1", 80, "127.0.0.1", 80), m("tcp", "127.0.0.1", 80, "127.0.0.1", 81)}}
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "already mapped by mapping 1") {
		t.Fatalf("duplicate: %v", err)
	}
	if err := (SSHHostLoopback{Enabled: true}).Validate(); err == nil {
		t.Fatal("enabled without mappings was accepted")
	}
	if err := (SSHHostLoopback{}).Validate(); err != nil {
		t.Fatal("a disabled empty configuration is valid:", err)
	}
	many := SSHHostLoopback{}
	for i := range MaxSSHHostLoopbackMappings + 1 {
		many.Mappings = append(many.Mappings, m("tcp", "127.0.0.1", uint16(1000+i), "127.0.0.1", 80))
	}
	if err := many.Validate(); err == nil {
		t.Fatal("too many mappings were accepted")
	}
}

func TestSSHHostLoopbackJSONAndInboundValidation(t *testing.T) {
	raw := `{"id":"ssh","name":"ssh","enabled":true,"network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:2222","udp":"tcp_only"}},"transports":[],
	"protocol":{"type":"ssh","ssh":{"hostKey":"","username":"u","authorizedKey":"","uid":0,"gid":0,"ipv6":true,"allowUnsafeShell":true,
	"hostLoopback":{"enabled":true,"mappings":[{"protocol":"tcp","sessionAddress":"127.0.0.1","sessionPort":5432,"hostAddress":"127.0.0.1","hostPort":5432}]}}}}`
	var in Inbound
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	in.Protocol.SSH.HostLoopback.Mappings[0].HostAddress = "10.0.0.1"
	if err := in.Validate(); err == nil {
		t.Fatal("Inbound.Validate must check host loopback mappings")
	}
	// Inbounds saved before the feature have no hostLoopback and stay valid.
	in.Protocol.SSH.HostLoopback = nil
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(in.Protocol.SSH)
	if strings.Contains(string(out), "hostLoopback") {
		t.Fatalf("a disabled feature must not appear in saved JSON: %s", out)
	}
}
