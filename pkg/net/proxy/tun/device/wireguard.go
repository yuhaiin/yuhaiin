package device

import (
	"math"

	"github.com/tailscale/wireguard-go/conn"
	wun "github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func IsGSOEnabled(device interface {
	BatchSize() int
},
) bool {
	// we can't get the value from the device
	// so check the batch size
	//
	// see: https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/tun_linux.go#L528C2-L543C4
	return device.BatchSize() == conn.IdealBatchSize
}

type wgDevice struct {
	wun.Device
	offset int
	mtu    int
}

func NewDevice(device wun.Device, offset, mtu int) *wgDevice {
	wrwc := &wgDevice{
		Device: device,
		offset: offset,
		mtu:    mtu,
	}

	return wrwc
}

func (t *wgDevice) Offset() int { return t.offset }
func (t *wgDevice) MTU() int    { return t.mtu }
func (t *wgDevice) Read(bufs [][]byte, sizes []int) (n int, err error) {
	return t.Device.Read(bufs, sizes, t.offset)
}

func (t *wgDevice) Write(bufs [][]byte) (int, error) {
	return t.Device.Write(bufs, t.offset)
}

func (t *wgDevice) Tun() wun.Device { return t.Device }

func ResetChecksum(ip header.Network, tp header.Transport, pseudoHeaderSum uint16) {
	ResetIPChecksum(ip)
	ResetTransportChecksum(ip, tp, pseudoHeaderSum)
}

func ResetIPChecksum(ip header.Network) {
	if ip, ok := ip.(header.IPv4); ok {
		ip.SetChecksum(0)
		sum := ip.CalculateChecksum()
		ip.SetChecksum(^sum)
	}
}

func ResetTransportChecksum(ip header.Network, tp header.Transport, pseudoHeaderSum uint16) {
	tp.SetChecksum(0)
	sum := checksum.Checksum(ip.Payload(), pseudoHeaderSum)

	//https://datatracker.ietf.org/doc/html/rfc768
	//
	// If the computed  checksum  is zero,  it is transmitted  as all ones (the
	// equivalent  in one's complement  arithmetic).   An all zero  transmitted
	// checksum  value means that the transmitter  generated  no checksum  (for
	// debugging or for higher level protocols that don't care).
	//
	// https://datatracker.ietf.org/doc/html/rfc8200
	// Unlike IPv4, the default behavior when UDP packets are
	//  originated by an IPv6 node is that the UDP checksum is not
	//  optional.  That is, whenever originating a UDP packet, an IPv6
	//  node must compute a UDP checksum over the packet and the
	//  pseudo-header, and, if that computation yields a result of
	//  zero, it must be changed to hex FFFF for placement in the UDP
	//  header.  IPv6 receivers must discard UDP packets containing a
	//  zero checksum and should log the error.
	if ip.TransportProtocol() != header.UDPProtocolNumber || sum != math.MaxUint16 {
		sum = ^sum
	}
	tp.SetChecksum(sum)
}
