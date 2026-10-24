package nat

import (
	"context"
	"net"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

// Real loopback datagrams exercise the shared NAT socket and both reply queues.
// One request/reply is outstanding; MB/s is not a WAN capacity measurement.
func BenchmarkAccessNATUDPRoundTrip(b *testing.B) {
	for _, mode := range []string{"Absent", "Disabled", "Protected", "Resources"} {
		b.Run(mode, func(b *testing.B) {
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			defer server.Close()
			peerDone := make(chan struct{})
			defer func() { _ = server.Close(); <-peerDone }()
			go func() {
				defer close(peerDone)
				buf := make([]byte, 65535)
				for {
					n, from, err := server.ReadFromUDP(buf)
					if err != nil {
						return
					}
					if _, err := server.WriteToUDP(buf[:n], from); err != nil {
						return
					}
				}
			}()
			table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) {
				socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					return nil, err
				}
				return &direct.UDPPacketConn{BufferPacketConn: direct.NewBufferPacketConn(socket)}, nil
			}})
			defer table.Close()
			if mode != "Absent" {
				c := accesscontrol.New()
				defer c.Close()
				if mode == "Protected" || mode == "Resources" {
					p, err := accesscontrol.Prepare(contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: "allow"})
					if err != nil {
						b.Fatal(err)
					}
					c.Activate(p)
				}
				table.SetTrafficAccess(c)
			}
			if mode == "Resources" {
				control := trafficcontrol.NewController()
				defer control.Close()
				profile := resource.Profile{Upload: resource.Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 30}, Download: resource.Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 30}}
				config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Profile: profile, Limits: resource.Limits{MaxSessions: 128}}, Groups: []resource.GroupPolicy{{GroupID: "finance", SharedProfile: profile}}}
				if err := control.ApplyResources(config, []trafficcontrol.IdentityBinding{{UserID: "alice", CredentialID: "phone", GroupIDs: []string{"finance"}}}); err != nil {
					b.Fatal(err)
				}
				table.SetTrafficControl(control, control.DatagramBudget())
			}
			dst, _ := netapi.ParseSysAddr(server.LocalAddr())
			received := make(chan int, 1)
			pkt := netapi.NewPacket(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}, dst, pool.GetBytes(1350), netapi.WriteBackFunc(func(data []byte, _ net.Addr) (int, error) { received <- len(data); return len(data), nil }), netapi.WithInboundID("entry"))
			defer pkt.DecRef()
			pkt.Identity = &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: b.Context()}
			watchdog := time.NewTimer(2 * time.Minute)
			defer watchdog.Stop()
			b.SetBytes(2700)
			b.ReportAllocs()
			for b.Loop() {
				if err := table.Write(b.Context(), pkt); err != nil {
					b.Fatal(err)
				}
				select {
				case n := <-received:
					if n != 1350 {
						b.Fatal(n)
					}
				case <-watchdog.C:
					b.Fatal("UDP benchmark timed out")
				}
			}
		})
	}
}
