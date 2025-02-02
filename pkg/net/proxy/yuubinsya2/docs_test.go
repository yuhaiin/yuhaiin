package yuubinsya2

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestHeader(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		username := "username"
		password := "password"
		header := EncodeHeader(username, password, TCP)
		protocol, err := DecodeHeader(bufio.NewReader(bytes.NewReader(header)), auth{
			f: func(user string, pass string) bool {
				return user == username && pass == password
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, protocol, TCP)

		t.Run("empty username and password", func(t *testing.T) {
			header := EncodeHeader("", "", TCP)
			_, err := DecodeHeader(bufio.NewReader(bytes.NewReader(header)), auth{
				f: func(user string, pass string) bool {
					return user == "" && pass == ""
				},
			})
			assert.NoError(t, err)
		})

		t.Run("invalid password", func(t *testing.T) {
			_, err := DecodeHeader(bufio.NewReader(bytes.NewReader(header)), auth{
				f: func(user string, pass string) bool {
					return user == username && pass == "invalid password"
				},
			})
			assert.Error(t, err)
		})
		t.Run("invalid username", func(t *testing.T) {
			_, err := DecodeHeader(bufio.NewReader(bytes.NewReader(header)), auth{
				f: func(user string, pass string) bool {
					return user == "invalid username" && pass == password
				},
			})
			assert.Error(t, err)
		})
	})

	t.Run("tcp header", func(t *testing.T) {
		addr, err := netapi.ParseAddress("tcp", "www.google.com:443")
		assert.NoError(t, err)
		data := []byte("hello")

		header := EncodeTCPHeader(addr, data)

		r := bufio.NewReader(bytes.NewReader(header))
		raddr, err := DecodeTCPHeader(r)
		assert.NoError(t, err)

		assert.Equal(t, raddr.Equal(addr), true)

		rdata, err := io.ReadAll(r)
		assert.NoError(t, err)

		assert.Equal(t, assert.ObjectsAreEqual(rdata, data), true)
	})

	t.Run("udp header", func(t *testing.T) {
		addr, err := netapi.ParseAddress("udp", "www.google.com:443")
		assert.NoError(t, err)
		data := []byte("hello")

		buf := EncodeUDPHeader(12, addr, data)

		r := bufio.NewReader(bytes.NewReader(buf))
		migrateID, raddr, rdata, err := DecodeUDPHeader(r)
		assert.NoError(t, err)

		assert.Equal(t, migrateID, 12)
		assert.Equal(t, raddr.Equal(addr), true)
		assert.Equal(t, assert.ObjectsAreEqual(rdata, data), true)
	})
}

type auth struct {
	f func(username, password string) bool
}

func (a auth) Verify(user string, password string) bool {
	return a.f(user, password)
}
