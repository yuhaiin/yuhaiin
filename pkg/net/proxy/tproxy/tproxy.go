package tproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type Tproxy struct {
	host string

	lis net.Listener

	lisAddr netip.AddrPort
	udp     net.PacketConn

	ctx    context.Context
	cancel context.CancelFunc

	udpChannel chan *netapi.Packet
	tcpChannel chan *netapi.StreamMeta
}

func init() {
	listener.RegisterProtocol2(NewTproxy)
}

func NewTproxy(opt *cl.Inbound_Tproxy) func(cl.InboundI) (netapi.ProtocolServer, error) {
	return func(ii cl.InboundI) (netapi.ProtocolServer, error) {
		ctx, cancel := context.WithCancel(context.Background())

		t := &Tproxy{
			host:       opt.Tproxy.Host,
			ctx:        ctx,
			cancel:     cancel,
			udpChannel: make(chan *netapi.Packet, 100),
			tcpChannel: make(chan *netapi.StreamMeta, 100),
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
	var err error

	t.cancel()

	if t.udp != nil {
		if er := t.udp.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if t.lis != nil {
		if er := t.lis.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
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
