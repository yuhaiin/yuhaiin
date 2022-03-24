package main

import (
	"log"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/stretchr/testify/require"
)

func TestCidr(t *testing.T) {
	cidrMatch := mapper.NewCidrMapper[string]()
	require.Nil(t, cidrMatch.Insert("10.2.2.1/18", "testIPv4"))
	require.Nil(t, cidrMatch.Insert("10.2.2.1/24", "testIPv42"))
	require.Nil(t, cidrMatch.Insert("2001:0db8:0000:0000:1234:0000:0000:9abc/32", "testIPv6"))
	require.Nil(t, cidrMatch.Insert("127.0.0.1/8", "testlocal"))
	require.Nil(t, cidrMatch.Insert("ff::/16", "testV6local"))

	search := func(s string) interface{} {
		res, _ := cidrMatch.Search(s)
		return res
	}

	testIPv4 := "10.2.3.1"
	testIPv42 := "10.2.2.1"
	testIPv4b := "100.2.2.1"
	testIPv6 := "2001:0db8:0000:0000:1234:0000:0000:9abc"
	testIPv6b := "3001:0db8:0000:0000:1234:0000:0000:9abc"

	log.Println("testIPv4", search(testIPv4))
	log.Println("testIPv42", search(testIPv42))
	log.Println("testIPv6", search(testIPv6))
	log.Println("testlocal", search("127.1.1.1"))
	log.Println(nil, search("129.1.1.1"))
	log.Println("testV6local", search("ff:ff::"))
	log.Println(nil, search(testIPv4b))
	log.Println(nil, search(testIPv6b))
}
