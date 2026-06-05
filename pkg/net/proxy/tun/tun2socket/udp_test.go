package tun2socket

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestGenerateUDPPacketAllocatesExactLength(t *testing.T) {
	payload := []byte("hello")
	packet, err := GenerateUDPPacket(1500, 4, payload, UDPTuple{
		SourceAddr:      tcpip.AddrFrom4([4]byte{1, 1, 1, 1}),
		DestinationAddr: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}),
		SourcePort:      1234,
		DestinationPort: 53,
	})
	assert.NoError(t, err)

	expected := 4 + 20 + 8 + len(payload)
	assert.MustEqual(t, expected, len(packet))
	assert.Equal(t, true, cap(packet) < 1500+4)
}
