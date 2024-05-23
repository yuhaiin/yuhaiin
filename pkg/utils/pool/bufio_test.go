package pool

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestBufioReaderPool(t *testing.T) {
	x := bytes.NewBuffer([]byte{})

	io.CopyN(x, rand.Reader, int64(MaxSegmentSize)*5)

	cc := make([]byte, x.Len())

	copy(cc, x.Bytes())

	r := GetBufioReader(x, MaxSegmentSize)

	yy := bytes.NewBuffer([]byte{})
	io.Copy(yy, r)

	PutBufioReader(r)

	t.Log(bytes.Equal(cc, yy.Bytes()))

	r = GetBufioReader(yy, MaxSegmentSize)

	zz := bytes.NewBuffer([]byte{})
	io.Copy(zz, r)

	PutBufioReader(r)

	t.Log(bytes.Equal(cc, zz.Bytes()))
}
