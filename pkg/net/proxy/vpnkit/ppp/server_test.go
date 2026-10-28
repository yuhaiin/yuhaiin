package ppp

import (
    "net"
    "testing"

    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/mschap"
)

type queuedTransport struct { packets *[][]byte }
func (t queuedTransport) SendPPP(frame []byte) error {
    *t.packets = append(*t.packets, append([]byte(nil), frame...))
    return nil
}
type testServerHandler struct { user string; up bool }
func (h *testServerHandler) ServerAuthenticated(user, _ string, _ [mschap.NTResponseLen]byte) { h.user = user }
func (h *testServerHandler) ServerNetworkUp() { h.up = true }

type testClientHandler struct { address net.IP; closed error }
func (h *testClientHandler) Authenticated(_ [mschap.NTResponseLen]byte) {}
func (h *testClientHandler) NetworkUp(cfg IPConfig) { h.address = cfg.LocalIP }
func (h *testClientHandler) Closed(err error) { h.closed = err }

func TestServerPPPInteroperatesWithClient(t *testing.T) {
    var clientPackets, serverPackets [][]byte
    clientHandler := &testClientHandler{}
    serverHandler := &testServerHandler{}
    client := New("alice", "correct", queuedTransport{&clientPackets}, clientHandler)
    server, err := NewServer(net.IPv4(10, 90, 0, 1), net.IPv4(10, 90, 0, 2), net.IPv4(1, 1, 1, 1),
        func(name string) (string, bool) { return "correct", name == "alice" },
        queuedTransport{&serverPackets}, serverHandler)
    if err != nil { t.Fatal(err) }
    if err := server.Start(); err != nil { t.Fatal(err) }
    client.Start()
    for i := 0; i < 100 && !(server.Up() && clientHandler.address != nil); i++ {
        for len(serverPackets) > 0 {
            frame := serverPackets[0]
            serverPackets = serverPackets[1:]
            client.Receive(frame)
        }
        for len(clientPackets) > 0 {
            frame := clientPackets[0]
            clientPackets = clientPackets[1:]
            if err := server.Receive(frame); err != nil { t.Fatal(err) }
        }
    }
    if !server.Up() || !serverHandler.up || serverHandler.user != "alice" {
        t.Fatalf("PPP server did not authenticate and configure link: %+v", serverHandler)
    }
    if !clientHandler.address.Equal(net.IPv4(10, 90, 0, 2)) {
        t.Fatalf("client address = %s, want 10.90.0.2", clientHandler.address)
    }
}

func TestServerPPPRejectsWrongPassword(t *testing.T) {
    var clientPackets, serverPackets [][]byte
    client := New("alice", "wrong", queuedTransport{&clientPackets}, &testClientHandler{})
    handler := &testServerHandler{}
    server, err := NewServer(net.IPv4(10, 90, 0, 1), net.IPv4(10, 90, 0, 2), nil,
        func(name string) (string, bool) { return "correct", name == "alice" },
        queuedTransport{&serverPackets}, handler)
    if err != nil { t.Fatal(err) }
    if err := server.Start(); err != nil { t.Fatal(err) }
    client.Start()
    for i := 0; i < 100; i++ {
        for len(serverPackets) > 0 {
            frame := serverPackets[0]
            serverPackets = serverPackets[1:]
            client.Receive(frame)
        }
        for len(clientPackets) > 0 {
            frame := clientPackets[0]
            clientPackets = clientPackets[1:]
            if err := server.Receive(frame); err != nil {
                if err != ErrAuth { t.Fatalf("expected ErrAuth, got %v", err) }
                if server.Up() || handler.up { t.Fatal("unauthenticated session became active") }
                return
            }
        }
    }
    t.Fatal("wrong password was not rejected")
}
