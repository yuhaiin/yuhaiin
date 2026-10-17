//go:build !darwin || ios

package lightweighttun

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"

func platformPacketIO(p *packetIO) lightweight.PacketIO { return p }
