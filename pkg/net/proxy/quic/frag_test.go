package quic

import (
	"bytes"
	"testing"
)

func TestFrag(t *testing.T) {
	f := Frag{}

	x := []byte(`
	sdadsacsacas
	VvsPKBDZyYauFZ0OvjsBrn3jUFpLZw4VJLwlXI6PKMvgJwPiiWcbwvSjbcUVkUBu
	MQswCQYDVQQGEwJVQTAgFw0yMzEwMTEwMDAwMDBaGA8yMTIzMTAxMTAzMjczNVowRjESMBAGA1UE
	AwwJMTI3LjAuMC4xMSMwIQYDVQQKDBpSZWdlcnksIGh0dHBzOi8vcmVnZXJ5LmNvbTELMAkGA1UE
sdadsacsacasa
	w7dd9uyDlVMFmHiNBlVDeLxMPJCyO7O13ktYY6td
Adda
	w7dd9uyDlVMFmHiNBlVDeLxMPJCyO7O13ktYY6td
	irtlS23Zr1qium5zAjrmk6eV4igiewV4AagcBnB9ydSEcf`)

	datas := f.Split(x, 50)

	t.Log(len(datas), len(x))

	for i, v := range datas {
		t.Log(i, len(v))
		if xx := f.Merge(v); xx != nil {
			t.Log(string(xx.Bytes()), bytes.Equal(xx.Bytes(), x))
		}
	}
}
