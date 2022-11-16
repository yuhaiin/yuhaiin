package domain

import "strings"

type domainReader struct {
	domain   string
	aft, pre int
}

func newDomainReader(domain string) *domainReader {
	return &domainReader{
		domain: domain,
		aft:    len(domain),
		pre:    strings.LastIndexByte(domain, '.') + 1,
	}
}

func (d *domainReader) hasNext() bool {
	return d.aft >= 0
}

func (d *domainReader) last() bool {
	return d.pre == 0
}

func (d *domainReader) next() bool {
	d.aft = d.pre - 1
	if d.aft < 0 {
		return false
	}
	d.pre = strings.LastIndexByte(d.domain[:d.aft], '.') + 1
	return true
}

func (d *domainReader) reset() {
	d.aft = len(d.domain)
	d.pre = strings.LastIndexByte(d.domain, '.') + 1
}

var valueEmpty = string([]byte{0x03})

func (d *domainReader) str() string {
	if d.pre == d.aft {
		return valueEmpty
	}
	return d.domain[d.pre:d.aft]
}
