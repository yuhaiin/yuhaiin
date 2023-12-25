package tproxy

import (
	"context"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type Tproxy struct {
	lis netapi.Listener

	lisAddr netip.AddrPort

	ctx    context.Context
	cancel context.CancelFunc

	udpChannel chan *netapi.Packet
	tcpChannel chan *netapi.StreamMeta
}

func init() {
	listener.RegisterProtocol2(NewTproxy)
}

func NewTproxy(opt *cl.Inbound_Tproxy) func(netapi.Listener) (netapi.ProtocolServer, error) {
	return func(ii netapi.Listener) (netapi.ProtocolServer, error) {
		ctx, cancel := context.WithCancel(context.Background())

		t := &Tproxy{
			ctx:        ctx,
			cancel:     cancel,
			udpChannel: make(chan *netapi.Packet, 100),
			tcpChannel: make(chan *netapi.StreamMeta, 100),
			lis:        ii,
		}

		if err := t.newTCP(); err != nil {
			return nil, err
		}

		if err := t.newUDP(); err != nil {
			t.Close()
			return nil, err
		}

		return t, nil
	}
}

func (t *Tproxy) Close() error {
	t.cancel()
	return t.lis.Close()
}

func (s *Tproxy) AcceptStream() (*netapi.StreamMeta, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case meta := <-s.tcpChannel:
		return meta, nil
	}
}

func (s *Tproxy) AcceptPacket() (*netapi.Packet, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case packet := <-s.udpChannel:
		return packet, nil
	}
}
