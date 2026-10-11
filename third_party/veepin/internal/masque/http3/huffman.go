package http3

// QPACK's string literals may be Huffman-coded, using — per RFC 9204 §5.2 — the
// exact code from RFC 7541 Appendix B, the same one HPACK uses. That table has
// 256 entries, and transcribing it by hand is the kind of thing that passes
// every round-trip test against itself and then silently corrupts one header
// against a real peer. golang.org/x/net/http2/hpack already carries a verified
// implementation of that identical code, and x/net is now a permitted
// dependency, so the decode is delegated to it rather than re-derived here.
//
// The encoder in qpack.go never emits Huffman, so only decode is needed; this
// keeps the wrapper to one function and one import.

import "golang.org/x/net/http2/hpack"

// huffmanDecode decodes an HPACK/QPACK Huffman-coded string.
func huffmanDecode(b []byte) (string, error) {
	s, err := hpack.HuffmanDecodeToString(b)
	if err != nil {
		return "", ErrQPACK
	}
	return s, nil
}
