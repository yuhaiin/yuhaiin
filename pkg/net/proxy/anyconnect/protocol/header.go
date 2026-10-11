package anyconnect

import "strconv"

// headerList is an ordered list of response headers written verbatim.
//
// net/http's Header canonicalizes names to Go's MIME form, which turns
// X-CSTP-MTU into X-Cstp-Mtu. That is correct HTTP — header names are
// case-insensitive — but AnyConnect clients compare these names case-sensitively
// and silently ignore a header whose case they do not recognise, so a canonical
// X-Cstp-Mtu reads to them as no MTU at all. Responses are therefore built here,
// with the exact casing the protocol uses, rather than through http.Header.
//
// Requests are still parsed with net/http, where canonicalization applies
// consistently to both the parsed names and our lookups.
type headerList [][2]string

func (h *headerList) set(name, value string) {
	for i := range *h {
		if (*h)[i][0] == name {
			(*h)[i][1] = value
			return
		}
	}
	*h = append(*h, [2]string{name, value})
}

func (h *headerList) add(name, value string) {
	*h = append(*h, [2]string{name, value})
}

func (h *headerList) setInt(name string, value int) {
	h.set(name, strconv.Itoa(value))
}
