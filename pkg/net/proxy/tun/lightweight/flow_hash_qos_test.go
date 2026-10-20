package lightweight

import "testing"

func TestOutputFlowHashIPv6ExtensionPorts(t *testing.T) {
	p := &ownedBuffer{data: make([]byte, 80)}
	b := p.data
	b[0] = 0x60
	b[6] = 0 // hop-by-hop extension
	b[7] = 64
	b[8], b[24] = 0xfd, 0xfd
	b[23], b[39] = 1, 2
	b[40] = 6 // TCP
	b[41] = 0 // 8-byte extension
	b[48], b[49], b[50], b[51] = 0x12, 0x34, 0, 80
	hash := outputFlowHash(p)
	b[49] = 0x35
	other := outputFlowHash(p)
	if hash == other {
		t.Fatal("IPv6 extension headers collapsed independent TCP flows")
	}
	b[49] = 0x34
	if hash != outputFlowHash(p) {
		t.Fatal("flow hash unstable")
	}
	// Fragmented packets deliberately share the same endpoint bucket.
	b[6] = 44
	first := outputFlowHash(p)
	b[42] = 0x01
	if first != outputFlowHash(p) {
		t.Fatal("fragment fields must not break the shared fragment bucket")
	}
}
