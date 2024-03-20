package pool

import "testing"

func TestBuffer(t *testing.T) {
	buf := GetBytesWriter(DefaultSize)
	defer buf.Free()

	_, _ = buf.Write([]byte("test"))
	_ = buf.WriteByte('c')
	buf.WriteString("test")

	t.Log(buf.String())

	t.Log(string(buf.Discard(1)))
	buf.Truncate(5)
	t.Log(buf.String())
	t.Log(string(buf.Discard(113)))
	t.Log(buf.String())
}
