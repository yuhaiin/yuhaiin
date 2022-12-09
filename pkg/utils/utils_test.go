package utils

import "testing"

func TestGetScheme(t *testing.T) {
	t.Log(GetScheme("http://www.baidu.com/dns-query"))
}

func TestDeleteSliceElem(t *testing.T) {
	z := []string{"a", "c"}

	t.Log(DeleteSliceElem(z, func(x string) bool { return x == "c" }))
}
