package connectip

import "testing"

func BenchmarkStreamBufferSmallReads(b *testing.B) {
	buffer := NewStreamBuffer()
	defer buffer.Close()
	payload := make([]byte, maxStreamBuffer)
	chunk := make([]byte, 1200)
	b.SetBytes(maxStreamBuffer)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := buffer.Write(payload); err != nil {
			b.Fatal(err)
		}
		for left := len(payload); left > 0; {
			n, err := buffer.Read(chunk[:min(len(chunk), left)])
			if err != nil {
				b.Fatal(err)
			}
			left -= n
		}
	}
}
