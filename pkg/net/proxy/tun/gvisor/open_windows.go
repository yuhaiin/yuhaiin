package tun

import (
	"crypto/md5"
	"fmt"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"golang.org/x/sys/windows"
	wun "golang.zx2c4.com/wireguard/tun"
)

const (
	offset = 0
)

func init() {
	wun.WintunTunnelType = "yuhaiin"
}

func OpenWriter(sc netlink.TunScheme, mtu int) (netlink.Writer, error) {
	if sc.Scheme != "tun" {
		return nil, fmt.Errorf("invalid tun: %v", sc)
	}

	device, err := wun.CreateTUNWithRequestedGUID(sc.Name,
		generateGUIDByDeviceName(sc.Name), mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun failed: %w", err)
	}

	return newWgReadWriteCloser(device), nil
}

func generateGUIDByDeviceName(name string) *windows.GUID {
	hash := md5.New()
	hash.Write([]byte("wintun"))
	hash.Write([]byte("yuhaiin"))
	hash.Write([]byte(name))
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0]))
}
