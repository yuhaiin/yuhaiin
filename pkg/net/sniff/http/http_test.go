package http

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestReader(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://ip.sb", nil)
	assert.NoError(t, err)

	buf := bytes.NewBuffer(nil)

	err = req.Write(buf)
	assert.NoError(t, err)

	r := &reader{b: buf.Bytes()}

	for {
		key, value, ok := r.ReadLine()
		if !ok {
			break
		}
		t.Log(string(key), string(value))
	}
}

func TestSniff(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://ip.sb:1234", nil)
	assert.NoError(t, err)

	buf := bytes.NewBuffer(nil)

	err = req.Write(buf)
	assert.NoError(t, err)

	assert.MustEqual(t, Sniff(buf.Bytes()), "ip.sb")
}
