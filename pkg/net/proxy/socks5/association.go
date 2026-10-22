package socks5

import (
	"context"
	"io"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

// User-authenticated UDP uses a relay port owned by this TCP association. The
// legacy shared UDP listener is not started in this mode.
func (s *Server) handleAuthenticatedUDP(client net.Conn, identity *proxyauth.Identity) error {
	requested, err := tools.ResolveAddr(client)
	if err != nil {
		return err
	}
	defer pool.PutBytes(requested)
	endpoint, err := netapi.ParseSysAddr(client.LocalAddr())
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(endpoint.String())
	if err != nil {
		return err
	}
	address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		return err
	}
	packet, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}
	defer packet.Close()
	stop := context.AfterFunc(s.ctx, func() { _ = client.Close(); _ = packet.Close() })
	defer stop()
	if identity != nil {
		stop := context.AfterFunc(identity.Context, func() { _ = client.Close(); _ = packet.Close() })
		defer stop()
	}
	remote, err := netip.ParseAddrPort(client.RemoteAddr().String())
	if err != nil {
		return err
	}
	filtered := &associationPacketConn{UDPConn: packet, ip: remote.Addr().Unmap(), port: requested.Address("udp").Port()}
	relay, err := netapi.ParseSysAddr(packet.LocalAddr())
	if err != nil {
		return err
	}
	if err = writeHandshake2(client, tools.Succeeded, relay); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = (&yuubinsya.UDPServer{PacketConn: filtered, Prefix: true, Handler: netapi.WithIdentityHandler(s.handler, identity).HandlePacket, MigrateID: nat.GenerateID(packet.LocalAddr())}).Serve()
	}()
	_, _ = io.Copy(io.Discard, client)
	_ = packet.Close()
	<-done
	return nil
}

type associationPacketConn struct {
	*net.UDPConn
	ip   netip.Addr
	port uint16
}

func (p *associationPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, remote, err := p.ReadFromUDPAddrPort(b)
		if err != nil {
			return 0, nil, err
		}
		if remote.Addr().Unmap() != p.ip || (p.port != 0 && remote.Port() != p.port) {
			continue
		}
		if p.port == 0 {
			p.port = remote.Port()
		}
		return n, net.UDPAddrFromAddrPort(remote), nil
	}
}
