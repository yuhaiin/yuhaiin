package domain

import "strings"

type fqdnReader struct {
	domain   string
	separate byte
	aft, pre int
}

func newFqdnReader(domain string) *fqdnReader {
	return newReader(domain, '.')
}

func newReader(domain string, separate byte) *fqdnReader {
	return &fqdnReader{
		domain:   domain,
		aft:      len(domain),
		separate: separate,
		pre:      strings.LastIndexByte(domain, separate) + 1,
	}
}

func (d *fqdnReader) hasNext() bool {
	return d.aft >= 0
}

func (d *fqdnReader) last() bool {
	return d.pre == 0
}

func (d *fqdnReader) next() bool {
	d.aft = d.pre - 1
	if d.aft < 0 {
		return false
	}
	d.pre = strings.LastIndexByte(d.domain[:d.aft], d.separate) + 1
	return true
}

func (d *fqdnReader) reset() {
	d.aft = len(d.domain)
	d.pre = strings.LastIndexByte(d.domain, d.separate) + 1
}

var valueEmpty = string([]byte{0x03})

func (d *fqdnReader) str() string {
	if d.pre == d.aft {
		return valueEmpty
	}
	return d.domain[d.pre:d.aft]
}
