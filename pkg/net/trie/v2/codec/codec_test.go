package codec

import (
	"encoding/binary"
	"slices"
	"testing"
)

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
