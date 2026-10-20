package lightweight

import "testing"

func FuzzOutputClassificationBounded(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6}, 0)
	f.Add([]byte{0x60, 0, 0, 0, 0, 0, 0, 17}, 0)
	f.Add([]byte{0x45}, 1)
	f.Fuzz(func(t *testing.T, data []byte, offset int) {
		packet := &ownedBuffer{data: data, offset: offset}
		_ = outputHostHash(packet)
		_ = outputFlowHash(packet)
		if weight := outputPacketWeight(packet); weight < 1 || weight > 4 {
			t.Fatalf("packet weight outside bounded control class: %d", weight)
		}
	})
}

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

func TestOutputPacketWeightBoundedControlClass(t *testing.T) {
	p := &ownedBuffer{data: make([]byte, 40)}
	b := p.data
	b[0] = 0x45
	b[9] = 6
	b[32] = 0x50
	b[33] = 0x10
	if got := outputPacketWeight(p); got != 4 {
		t.Fatalf("pure TCP ACK weight=%d", got)
	}
	b = append(b, 0x01, 0x02)
	p.data = b
	if got := outputPacketWeight(p); got != 1 {
		t.Fatalf("bulk TCP payload weight=%d", got)
	}
	b[33] = 0x02 // SYN
	if got := outputPacketWeight(p); got != 4 {
		t.Fatalf("TCP SYN weight=%d", got)
	}
	b[9] = 17 // ordinary UDP
	if got := outputPacketWeight(p); got != 1 {
		t.Fatalf("UDP bypass weight=%d", got)
	}
	b[9] = 1
	if got := outputPacketWeight(p); got != 2 {
		t.Fatalf("ICMP weight=%d", got)
	}
}
