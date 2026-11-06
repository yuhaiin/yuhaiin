package interfaces

import (
	"strconv"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func stableInterfaceID(iface Interface) (string, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return "", err
	}
	return "luid:" + strconv.FormatUint(uint64(luid), 10), nil
}
