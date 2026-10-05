package disk

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

func TestCompressedReaderRejectsInvalidRootLinks(t *testing.T) {
	dir := t.TempDir()
	trie, err := NewTrie[string](dir, codec.UnsafeStringCodec{})
	if err != nil {
		t.Fatal(err)
	}
	trie.InsertCIDR(netip.MustParsePrefix("2001:db8::1/128"), "host")
	if err := trie.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(globSegments(dir)[0])
	if err != nil {
		t.Fatal(err)
	}
	root := int(binary.LittleEndian.Uint64(data[48:]))
	rootOff := segmentHeaderSize + root*segmentNodeSize
	jumpOff := int(binary.LittleEndian.Uint64(data[56:]))
	for name, mutate := range map[string]func([]byte){
		"root cycle":        func(data []byte) { binary.LittleEndian.PutUint64(data[rootOff+8:], uint64(root)) },
		"jump cycle":        func(data []byte) { binary.LittleEndian.PutUint64(data[jumpOff:], uint64(root)) },
		"jump out of range": func(data []byte) { binary.LittleEndian.PutUint64(data[rootOff+8:], jumpTag|128<<jumpShift|jumpMask) },
		"zero skip":         func(data []byte) { binary.LittleEndian.PutUint64(data[rootOff+8:], jumpTag) },
		"oversized skip":    func(data []byte) { binary.LittleEndian.PutUint64(data[rootOff+8:], jumpTag|129<<jumpShift) },
		"IPv4 width": func(data []byte) {
			link := binary.LittleEndian.Uint64(data[rootOff+8:])
			binary.LittleEndian.PutUint64(data[rootOff:], link)
			binary.LittleEndian.PutUint64(data[rootOff+8:], absentChild)
		},
		"unaligned jump area": func(data []byte) { binary.LittleEndian.PutUint64(data[32:], uint64(jumpOff+1)) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := slices.Clone(data)
			mutate(copy)
			path := filepath.Join(t.TempDir(), "bad.cidr")
			if err := os.WriteFile(path, copy, 0600); err != nil {
				t.Fatal(err)
			}
			segment, err := openSegment[string](path, codec.UnsafeStringCodec{})
			if err == nil {
				segment.close()
				t.Fatal("accepted invalid root")
			}
		})
	}
}

func TestConcurrentSearchDuringCompressedCompaction(t *testing.T) {
	trie, err := NewTrie[string](t.TempDir(), codec.UnsafeStringCodec{}, WithMemoryLimit(4096))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	trie.InsertCIDR(netip.MustParsePrefix("2001:db8::/32"), "stable")
	if err := trie.Sync(); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			ip := net.ParseIP("2001:db8::1")
			for {
				select {
				case <-stop:
					return
				default:
				}
				if got := trie.SearchIP(ip); !slices.Equal(got, []string{"stable"}) {
					t.Errorf("Search = %v", got)
					return
				}
			}
		})
	}
	for index := range 1000 {
		var bytes [16]byte
		bytes[0], bytes[1], bytes[2], bytes[3] = 0x20, 0x01, 0x0d, 0xb8
		bytes[8], bytes[9], bytes[14], bytes[15] = byte(index>>8), byte(index), 1, 2
		trie.InsertCIDR(netip.PrefixFrom(netip.AddrFrom16(bytes), 128), "updated")
	}
	err = trie.Sync()
	close(stop)
	readers.Wait()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompressedSegmentWithGenericCodec(t *testing.T) {
	trie, err := NewTrie[int](t.TempDir(), codec.GobCodec[int]{}, WithMemoryLimit(1))
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	for _, rule := range []struct {
		prefix string
		mark   int
	}{
		{"2001:db8::/32", 1}, {"2001:db8::1/128", 2}, {"2001:db8::/64", 1}, {"2001:db8::1/128", 3},
	} {
		trie.InsertCIDR(netip.MustParsePrefix(rule.prefix), rule.mark)
	}
	if err := trie.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := trie.SearchIP(net.ParseIP("2001:db8::1")); !slices.Equal(got, []int{1, 2, 3}) {
		t.Fatalf("Search = %v", got)
	}
}
