package pool

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestBufioReaderPool(t *testing.T) {
	x := bytes.NewBuffer([]byte{})

	_, err := io.CopyN(x, rand.Reader, int64(MaxSegmentSize)*5)
	assert.NoError(t, err)

	cc := make([]byte, x.Len())

	copy(cc, x.Bytes())

	r := GetBufioReader(x, MaxSegmentSize)

	yy := bytes.NewBuffer([]byte{})
	_, err = io.Copy(yy, r)
	assert.NoError(t, err)

	PutBufioReader(r)

	t.Log(bytes.Equal(cc, yy.Bytes()))

	r = GetBufioReader(yy, MaxSegmentSize)

	zz := bytes.NewBuffer([]byte{})
	_, err = io.Copy(zz, r)
	assert.NoError(t, err)

	PutBufioReader(r)

	t.Log(bytes.Equal(cc, zz.Bytes()))
}

func TestXxx(t *testing.T) {
	b := bytes.NewBuffer([]byte("dsadasdcxzczczasdasd"))

	br := GetBufioReader(b, 1024)

	n, err := br.Read([]byte{0x00})
	assert.NoError(t, err)

	t.Log(n, br.Buffered())

	err = br.UnreadByte()
	assert.NoError(t, err)

	t.Log(n, br.Buffered())
}
