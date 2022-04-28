package dns

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestXxx(t *testing.T) {
	domain := "www.google.com."
	for i := strings.IndexByte(domain, '.'); i != -1; i = strings.IndexByte(domain, '.') {
		fmt.Println(domain[:i], i)
		domain = domain[i+1:]
	}
}

func TestReader(t *testing.T) {
	domain := "www.google.com."

	b := bytes.NewBuffer(nil)
	for i := strings.IndexByte(domain, '.'); i != -1; i = strings.IndexByte(domain, '.') {
		b.WriteByte(byte(i))
		b.WriteString(domain[:i])
		domain = domain[i+1:]
	}
	b.WriteByte(0)
	b.WriteByte(192)
	b.WriteByte(0)

	t.Log(b.Bytes())

	r := newReader(b.Bytes())

	t.Log(r.domain(r.r))
	t.Log(r.r.Bytes())
	t.Log(r.domain(r.r))

}
