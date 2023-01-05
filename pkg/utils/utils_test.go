package utils

import "testing"

func TestGetScheme(t *testing.T) {
	t.Log(GetScheme("http://www.baidu.com/dns-query"))
}
