package tproxy

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type Tproxy struct {
	udp *udpserver
	tcp *tcpserver
}

func NewTproxy(opt *cl.Opts[*cl.Protocol_Tproxy]) (netapi.Server, error) {
	udp, err := newUDP(opt)
	if err != nil {
		return nil, err
	}

	tcp, err := newTCP(opt)
	if err != nil {
		udp.Close()
		return nil, err
	}

	return &Tproxy{
		udp: udp,
		tcp: tcp,
	}, nil
}

func (t *Tproxy) Close() error {
	var err error

	if er := t.udp.Close(); er != nil {
		err = errors.Join(err, er)
	}

	if er := t.tcp.Close(); er != nil {
		err = errors.Join(err, er)
	}

	return err
}
