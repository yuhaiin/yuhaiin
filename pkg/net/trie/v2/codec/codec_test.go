package codec

import (
	"encoding/binary"
	"slices"
	"testing"
)

func TestAppendDecodeOwned(t *testing.T) {
	decoder, ok := any(UnsafeStringCodec{}).(interface {
		AppendDecodeOwned([]string, []byte) ([]string, error)
	})
	if !ok {
		t.Fatal("codec has no owned append decoder")
	}
	data, err := (UnsafeStringCodec{}).Encode([]string{"existing", "new-owned-value", "new-owned-value", ""})
	if err != nil {
		t.Fatal(err)
	}
	got, err := decoder.AppendDecodeOwned([]string{"existing"}, data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	if !slices.Equal(got, []string{"existing", "new-owned-value", ""}) {
		t.Fatalf("owned values = %q", got)
	}
	duplicates, err := (UnsafeStringCodec{}).Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		_, err := decoder.AppendDecodeOwned(got, duplicates)
		if err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("duplicate decode allocated %g times", allocs)
	}
	for _, data := range [][]byte{{1, 0, 0, 0}, {1, 0, 0, 0, 3, 0, 0, 0, 'a', 'b'}, {0, 0, 0, 0, 1}, append(duplicates, 1)} {
		result, err := decoder.AppendDecodeOwned(got, data)
		if err == nil || !slices.Equal(result, got) {
			t.Fatalf("malformed decode = %q, %v", result, err)
		}
	}
}

func TestUnsafeStringCodecRoundTripsEmptyAndNonEmptyValues(t *testing.T) {
	want := []string{"", "host.example", "another"}
	encoded, err := (UnsafeStringCodec{}).Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (UnsafeStringCodec{}).Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Decode(Encode(values)) = %q, want %q", got, want)
	}
}

func TestUnsafeStringCodecRejectsMalformedValues(t *testing.T) {
	badValues := [][]byte{
		{1, 0, 0, 0},                       // count without a length
		{1, 0, 0, 0, 3, 0, 0, 0, 'a', 'b'}, // truncated value
		{0, 0, 0, 0, 1},                    // trailing bytes
	}
	for _, data := range badValues {
		if _, err := (UnsafeStringCodec{}).Decode(data); err == nil {
			t.Errorf("Decode(%v) succeeded, want malformed-data error", data)
		}
	}

	tooMany := make([]byte, 4)
	binary.LittleEndian.PutUint32(tooMany, ^uint32(0))
	if _, err := (UnsafeStringCodec{}).Decode(tooMany); err == nil {
		t.Fatal("Decode of an impossible item count succeeded")
	}
}

// Only the original Codec methods are exposed, so this exercises fallback
// ownership and deduplication with a decoder returning borrowed strings.
type decodeOnlyStringCodec struct{}

func (decodeOnlyStringCodec) Encode(v []string) ([]byte, error) {
	return (UnsafeStringCodec{}).Encode(v)
}
func (decodeOnlyStringCodec) Decode(b []byte) ([]string, error) {
	return (UnsafeStringCodec{}).Decode(b)
}
func TestAppendUniqueOwnedFallback(t *testing.T) {
	c := decodeOnlyStringCodec{}
	data, err := c.Encode([]string{"existing", "owned", "owned"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := AppendUniqueOwned[string](c, []string{"existing"}, data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	if !slices.Equal(got, []string{"existing", "owned"}) {
		t.Fatalf("values = %q", got)
	}
	ints := GobCodec[int]{}
	data, err = ints.Encode([]int{1, 2, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	result, err := AppendUniqueOwned[int](ints, []int{1}, data)
	if err != nil || !slices.Equal(result, []int{1, 2, 3}) {
		t.Fatalf("values = %v, error = %v", result, err)
	}
}

func TestAppendEncodingRetainsPrefixAndReusesStorage(t *testing.T) {
	c := UnsafeStringCodec{}
	values := []string{"", "geosite-cn", "route-name"}
	expected, err := c.Encode(values)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 3, 256)
	copy(buffer, []byte("pre"))
	if allocs := testing.AllocsPerRun(100, func() {
		var err error
		buffer, err = AppendEncode[string](c, buffer[:3], values)
		if err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("encoding allocs=%g", allocs)
	}
	if string(buffer[:3]) != "pre" || !slices.Equal(buffer[3:], expected) {
		t.Fatal("encoded bytes changed")
	}
	if c.EncodedSize(values) != uint64(len(expected)) {
		t.Fatal("incorrect encoded size")
	}
	generic := GobCodec[int]{}
	data, err := AppendEncode[int](generic, []byte("pre"), []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	got, err := generic.Decode(data[3:])
	if err != nil || !slices.Equal(got, []int{1, 2}) {
		t.Fatalf("generic=%v, %v", got, err)
	}
}
