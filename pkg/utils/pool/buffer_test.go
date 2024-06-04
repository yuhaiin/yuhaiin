package pool

import (
	"bytes"
	"testing"
)

func TestBuffer(t *testing.T) {
	var b Buffer
	var bb bytes.Buffer

	for _, v := range [][]byte{
		[]byte("hello"),
		[]byte("world"),
	} {

		_, _ = b.Write(v)
		_, _ = bb.Write(v)

	}

	if !bytes.Equal(b.Bytes(), bb.Bytes()) {
		t.Fail()
	}
}
