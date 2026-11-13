//go:build !(linux && !android) && !darwin && !windows

package iface

import (
	"net"
	"net/netip"
)

func platformType(net.Interface) string { return "" }

func platformGateways() map[int][2]netip.Addr { return nil }
