package netapi

// BufferReader waits for readable data before borrowing a buffer. Wrappers can
// preserve this capability without exposing the underlying connection or
// bypassing accounting. It has the same EOF and deadline semantics as Read.
//
// ReadWithBuffer calls getBuffer at most once. The returned buffer belongs to
// the caller, which must return it to its pool after consuming it, including
// when data is returned together with an error. A nil buffer needs no release.
type BufferReader interface {
	ReadWithBuffer(getBuffer func() []byte) ([]byte, error)
}
