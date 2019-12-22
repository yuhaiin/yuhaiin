package getproxyconn

import (
	"net/url"
	"testing"
)

func TestForward(t *testing.T) {
	URI, err := url.Parse("socks5://127.0.0.1:7891")
	if err != nil {
		t.Error(err)
	}
	t.Log(ForwardTo("www.google.com:443", *URI))

	URI, err = url.Parse("http://127.0.0.1:7980")
	if err != nil {
		t.Error(err)
	}
	t.Log(ForwardTo("www.google.com:443", *URI))
}
