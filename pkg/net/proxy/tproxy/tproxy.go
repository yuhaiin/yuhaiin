package tproxy

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Tproxy struct {
	udp *udpserver
	tcp *tcpserver
}

func NewTproxy(opt *cl.Opts[*cl.Protocol_Tproxy]) (netapi.Server, error) {
	udp, err := newUDP(opt.Protocol.Tproxy.Host, opt.Handler, opt.DNSHandler)
	if err != nil {
		return nil, err
	}

	tcp, err := newTCP(opt.Protocol.Tproxy.Host, opt.Handler, opt.DNSHandler)
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

type udpserver struct {
	lis net.PacketConn
}

func (u *udpserver) Close() error {
	return u.lis.Close()
}

func isHandleDNS(port uint16) bool {
	return port == 53
}

func newUDP(host string, handler netapi.Handler, dnsHandler netapi.DNSHandler) (*udpserver, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, err
	}
	lis, err := dialer.ListenPacketWithOptions("udp", udpAddr.String(), &dialer.Options{
		MarkSymbol: func(socket int32) bool {
			return dialer.LinuxMarkSymbol(socket, 0xff) == nil
		},
	})
	if err != nil {
		return nil, err
	}

	udpLis, ok := lis.(*net.UDPConn)
	if !ok {
		lis.Close()
		return nil, fmt.Errorf("listen is not udplistener")
	}

	sysConn, err := udpLis.SyscallConn()
	if err != nil {
		lis.Close()
		return nil, err
	}

	err = controlUDP(sysConn)
	if err != nil {
		lis.Close()
		return nil, err
	}
	log.Info("new tproxy udp server", "host", lis.LocalAddr())

	s := &udpserver{lis: lis}

	go func() {
		for {
			buf := pool.GetBytesV2(nat.MaxSegmentSize)
			n, src, dst, err := ReadFromUDP(udpLis, buf.Bytes())
			if err != nil {
				log.Error("start udp server failed", "err", err)
				break
			}

			if isHandleDNS(uint16(dst.Port)) {
				err := dnsHandler.Do(context.TODO(), buf.Bytes()[:n], func(b []byte) error {
					defer pool.PutBytesV2(buf)
					back, err := DialUDP("udp", dst, src)
					if err != nil {
						return fmt.Errorf("udp server dial failed: %w", err)
					}
					defer back.Close()
					_, err = back.Write(b)
					return err
				})
				if err != nil {
					log.Error("udp server handle DnsHijacking failed", "err", err)
				}
				continue
			}

			dstAddr, _ := netapi.ParseSysAddr(dst)
			handler.Packet(context.TODO(), &netapi.Packet{
				Src:     src,
				Dst:     dstAddr,
				Payload: buf.Bytes()[:n],
				WriteBack: func(b []byte, addr net.Addr) (int, error) {
					defer pool.PutBytesV2(buf)

					ad, err := netapi.ParseSysAddr(addr)
					if err != nil {
						return 0, err
					}

					uaddr, err := ad.UDPAddr(context.Background())
					if err != nil {
						return 0, err
					}

					back, err := DialUDP("udp", uaddr, src)
					if err != nil {
						return 0, fmt.Errorf("udp server dial failed: %w", err)
					}
					defer back.Close()

					n, err := back.Write(b)
					if err != nil {
						return 0, err
					}

					return n, nil
				},
			})
		}
	}()

	return s, nil
}

type tcpserver struct {
	lis net.Listener
}

func (t *tcpserver) Close() error { return t.lis.Close() }

func newTCP(host string, p netapi.Handler, dnsHandler netapi.DNSHandler) (*tcpserver, error) {
	lis, err := dialer.ListenContextWithOptions(context.TODO(), "tcp", host, &dialer.Options{
		MarkSymbol: func(socket int32) bool {
			return dialer.LinuxMarkSymbol(socket, 0xff) == nil
		},
	})
	if err != nil {
		return nil, err
	}

	f, err := lis.(*net.TCPListener).SyscallConn()
	if err != nil {
		return nil, err
	}

	err = controlTCP(f)
	if err != nil {
		lis.Close()
		return nil, err
	}

	log.Info("new tproxy tcp server", "host", host)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("tcp server accept failed", "err", err)
				break
			}

			go func() {
				if err := handleTCP(conn, p, dnsHandler); err != nil {
					log.Error("tcp server handle failed", "err", err)
				}
			}()
		}
	}()

	return &tcpserver{lis: lis}, nil
}
