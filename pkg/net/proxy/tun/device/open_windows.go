package device

import (
	"crypto/md5"
	"fmt"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	wun "github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
)

const (
	offset = 0
)

func init() {
	wun.WintunTunnelType = "yuhaiin"
}

func OpenWriter(sc netlink.TunScheme, mtu int) (netlink.Tun, error) {
	if sc.Scheme != "tun" {
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}

	device, err := wun.CreateTUNWithRequestedGUID(sc.Name,
		generateGUIDByDeviceName(sc.Name), mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return NewDevice(device, offset, mtu), nil
}

func generateGUIDByDeviceName(name string) *windows.GUID {
	hash := md5.New()
	hash.Write([]byte("wintun"))
	hash.Write([]byte("yuhaiin"))
	hash.Write([]byte(name))
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0]))
}

func (d *wgDevice) LUID() uint64 {
	return d.Device.(*wun.NativeTun).LUID()
}
