package quic

import (
	"fmt"
	"testing"
)

func compareConstantTime(num int) int {
	fmt.Println(num | -num)
	fmt.Println((num | -num) >> 31)
	return ((num | -num) >> 31) & 1
}

func TestFrag(t *testing.T) {
	t.Log(compareConstantTime(100))
	t.Log(compareConstantTime(102))
	t.Log(compareConstantTime(1022))
	t.Log(compareConstantTime(0))

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
		t.Log(i, v.Len())
		if x := f.Merge(v.Bytes()); x != nil {
			t.Log(string(x.Bytes()))
		}
	}
}
