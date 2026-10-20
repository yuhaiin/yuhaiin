package lightweight

import "testing"

func TestOutputHostHashIgnoresSourceAndPortsButNotDestination(t *testing.T) {
	packet := &ownedBuffer{data: make([]byte, 60)}
	b := packet.data
	b[0] = 0x45
	b[12], b[13], b[14], b[15] = 1, 2, 3, 4
	b[16], b[17], b[18], b[19] = 10, 0, 0, 1
	a := outputHostHash(packet)
	b[12]++
	b[20], b[21] = 0xff, 0xff
	if h := outputHostHash(packet); h != a {
		t.Fatal("client group split by source or transport")
	}
	b[19]++
	if h := outputHostHash(packet); h == a {
		t.Fatal("independent destinations collided")
	}
	b[0] = 0x60
	b[24], b[39] = 0xfd, 1
	ip6 := outputHostHash(packet)
	b[39]++
	if h := outputHostHash(packet); h == ip6 {
		t.Fatal("IPv6 host identity not separated")
	}
	packet.offset = -1
	if h := outputHostHash(packet); h != 0 {
		t.Fatal("invalid packet must use shared fallback group")
	}
}

func BenchmarkOutputHostHashIPv4(b *testing.B) {
	packet := &ownedBuffer{data: make([]byte, 1500)}
	packet.data[0] = 0x45
	packet.data[16] = 192
	packet.data[17] = 0
	packet.data[18] = 2
	packet.data[19] = 1
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = outputHostHash(packet)
	}
}
