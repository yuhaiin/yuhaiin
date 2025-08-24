package tun2socket

import (
	"net/netip"

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

		dstAddr, ok := netip.AddrFromSlice(dst.AsSlice())
		if !ok {
			return
		}

		srcAddr, ok := netip.AddrFromSlice(src.AsSlice())
		if !ok {
			return
		}

		writeBack := func(id uint64, err error) error {
			ip.SetDestinationAddress(src)
			ip.SetSourceAddress(dst)

			if err != nil {
				i.SetType(header.ICMPv4DstUnreachable)
			}

			device.ResetChecksum(ip, i, 0)
			_, err = p.opt.Device.Write([][]byte{data})
			return err
		}

		if dstAddr.IsLoopback() || p.opt.V4Contains(dstAddr) || !p.opt.V4Contains(srcAddr) {
			_ = writeBack(0, nil)
			return
		}

		p.opt.HandlePing(&netapi.PingMeta{
			Source:      netapi.ParseNetipAddr("udp", srcAddr, 0),
			Destination: netapi.ParseNetipAddr("udp", dstAddr, 0),
			WriteBack:   writeBack,
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

		src := ip.SourceAddress()
		dst := ip.DestinationAddress()

		dstAddr, ok := netip.AddrFromSlice(dst.AsSlice())
		if !ok {
			return
		}

		srcAddr, ok := netip.AddrFromSlice(src.AsSlice())
		if !ok {
			return
		}

		writeBack := func(id uint64, err error) error {
			ip.SetDestinationAddress(src)
			ip.SetSourceAddress(dst)

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
		}

		if dstAddr.IsLoopback() || p.opt.V6Contains(dstAddr) || !p.opt.V6Contains(srcAddr) {
			_ = writeBack(0, nil)
			return
		}

		p.opt.HandlePing(&netapi.PingMeta{
			Source:      netapi.ParseNetipAddr("udp", srcAddr, 0),
			Destination: netapi.ParseNetipAddr("udp", dstAddr, 0),
			WriteBack:   writeBack,
		})
	}()
}
