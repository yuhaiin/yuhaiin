package main

import (
	"fmt"
	"regexp"

	"../../base64d"
)

func test_s(link string) {

	re, _ := regexp.Compile("(ssr*)://(.*)")
	ssRe, _ := regexp.Compile("(.*):(.*)@(.*):([0-9]*)")
	ssrRe, _ := regexp.Compile("(.*):([0-9]*):(.*):(.*):(.*):(.*)/?obfsparam=(.*)&protoparam=(.*)&remarks=(.*)&group=(.*)")
	ssOrSsr := re.FindAllStringSubmatch(link, -1)
	switch ssOrSsr[0][1] {
	case "ss":
		ss := ssRe.FindAllStringSubmatch(ssOrSsr[0][2], -1)[0]
		template := "ss"
		method := ss[1]
		password := base64d.Base64d(ss[2])
		server := ss[3]
		server_port := ss[4]
		fmt.Println(template, server, server_port, method, password)

	case "ssr":
		ssr := ssrRe.FindAllStringSubmatch(ssOrSsr[0][2], -1)[0]
		template := "ssr"
		server := ssr[1]
		server_port := ssr[2]
		protocol := ssr[3]
		method := ssr[4]
		obfs := ssr[5]
		password := base64d.Base64d(ssr[6])
		obfsparam := base64d.Base64d(ssr[7])
		protoparam := base64d.Base64d(ssr[8])
		remarks := base64d.Base64d(ssr[9])
		fmt.Println(template, remarks, server, server_port, protocol, method, obfs, password, obfsparam, protoparam)
	}
}
func main() {

	ss := "ss://aes-256-cfb:6aKd5oGp6Lqr@1.1.1.1:53"
	ssr := "ssr://1.1.1.1:53:auth_chain_a:none:http_simple:6aKd5oGp6Lqr/?obfsparam=6aKd5oGp6Lqr&protoparam=6aKd5oGp6Lqr&remarks=6aKd5oGp6Lqr&group=6aKd5oGp6Lqr"
	test_s(ss)
	test_s(ssr)
}
