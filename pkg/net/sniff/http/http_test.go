package http

import (
	"bytes"
	"encoding/base64"
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
	t.Run("domain", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://ip.sb:1234", nil)
		assert.NoError(t, err)

		buf := bytes.NewBuffer(nil)

		err = req.Write(buf)
		assert.NoError(t, err)

		assert.MustEqual(t, Sniff(buf.Bytes()), "ip.sb")
	})

	t.Run("ipv4", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://1.2.4.5", nil)
		assert.NoError(t, err)

		buf := bytes.NewBuffer(nil)

		err = req.Write(buf)
		assert.NoError(t, err)

		assert.MustEqual(t, "1.2.4.5", Sniff(buf.Bytes()))
	})

	t.Run("ipv6", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://[ff::ff]", nil)
		assert.NoError(t, err)

		buf := bytes.NewBuffer(nil)

		err = req.Write(buf)
		assert.NoError(t, err)

		assert.MustEqual(t, "ff::ff", Sniff(buf.Bytes()))
	})

	t.Run("ipv6 with port", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://[ff::ff]:80", nil)
		assert.NoError(t, err)

		buf := bytes.NewBuffer(nil)

		err = req.Write(buf)
		assert.NoError(t, err)

		assert.MustEqual(t, "ff::ff", Sniff(buf.Bytes()))
	})
}

func TestSniffy(t *testing.T) {
	data := "UE9TVCAvYXBpIEhUVFAvMS4xDQpIb3N0OiBbMjAwMTpiMjg6ZjIzZjpmMDA1OjphXTo4MA0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAxNzYNCkNvbm5lY3Rpb246IEtlZXAtQWxpdmUNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZQ0KQWNjZXB0LUxhbmd1YWdlOiBlbi1KUCwqDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMA0KDQo="

	raw, err := base64.StdEncoding.DecodeString(data)
	assert.NoError(t, err)

	assert.MustEqual(t, Sniff(raw), "2001:b28:f23f:f005::a")
}
