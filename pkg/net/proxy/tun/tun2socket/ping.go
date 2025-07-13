package tun2socket

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Ping struct {
	opt *device.Opt
}

func (p *Ping) HandlePing4(bytes []byte) {
	data := pool.Clone(bytes)

	go func() {
		defer pool.PutBytes(data)

		ip := header.IPv4(data[p.opt.Device.Offset():])

		i := header.ICMPv4(ip.Payload())

		if i.Type() != header.ICMPv4Echo || i.Code() != 0 {
			return
		}

		i.SetType(header.ICMPv4EchoReply)

		src := ip.SourceAddress()
		dst := ip.DestinationAddress()

		p.opt.Handler.HandlePing(&netapi.PingMeta{
			Source:      netapi.ParseIPAddr("udp", src.AsSlice(), 0),
			Destination: netapi.ParseIPAddr("udp", dst.AsSlice(), 0),
			WriteBack: func(id uint64, err error) error {
				if err != nil {
					i.SetType(header.ICMPv4DstUnreachable)
				}

				destination := ip.DestinationAddress()
				ip.SetDestinationAddress(ip.SourceAddress())
				ip.SetSourceAddress(destination)

				device.ResetChecksum(ip, i, 0)
				_, err = p.opt.Device.Write([][]byte{data})
				return err
			},
		})
	}()
}

func (p *Ping) HandlePing6(bytes []byte) {
	data := pool.Clone(bytes)

	go func() {
		defer pool.PutBytes(data)

		ip := header.IPv6(data[p.opt.Device.Offset():])
		i := header.ICMPv6(ip.Payload())

		if i.Type() != header.ICMPv6EchoRequest || i.Code() != 0 {
			return
		}

		i.SetType(header.ICMPv6EchoReply)

		destination := ip.DestinationAddress()
		ip.SetDestinationAddress(ip.SourceAddress())
		ip.SetSourceAddress(destination)

		src := ip.SourceAddress()
		dst := ip.DestinationAddress()
		p.opt.Handler.HandlePing(&netapi.PingMeta{
			Source:      netapi.ParseIPAddr("udp", src.AsSlice(), 0),
			Destination: netapi.ParseIPAddr("udp", dst.AsSlice(), 0),
			WriteBack: func(id uint64, err error) error {
				if err != nil {
					i.SetType(header.ICMPv6DstUnreachable)
				}

				pseudoHeaderSum := header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber,
					ip.SourceAddress(), ip.DestinationAddress(),
					uint16(len(i)),
				)

				device.ResetChecksum(ip, i, pseudoHeaderSum)

				_, err = p.opt.Device.Write([][]byte{data})
				return err
			},
		})
	}()
}
