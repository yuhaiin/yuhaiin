package utils

import (
	_ "net/url"
	"runtime"
	_ "unsafe"
)

//go:linkname GetScheme net/url.getScheme
func GetScheme(ur string) (scheme, etc string, err error)

var Procs = func() int {
	procs := runtime.GOMAXPROCS(0)
	if procs < 4 {
		return 4
	}
	return procs
}()

var UserAgentLength = len(UserAgents)

var UserAgents = []string{
	"",
	"curl/7.1.2",
	"curl/7.2.3",
	"curl/7.1.3",
	"curl/7.1.4",
	"curl/7.1.5",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/99.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/101.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/102.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/99.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/101.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/102.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.6743.241 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.6743.241 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.6743.241 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.6743.241 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3239.83 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.3239.83 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.3239.83 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.3239.83 Mobile Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.2272.89 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.2272.89 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.2272.89 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.2272.89 Safari/537.36",
}
