package dns

import (
	"encoding/base64"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

// https://tools.ietf.org/html/rfc8484
func DOH(server string, domain string) (DNS []net.IP, err error) {
	req := creatRequest(domain, A)
	//log.Println(req)

	query := strings.Replace(base64.URLEncoding.EncodeToString(req), "=", "", -1)
	url := "https://" + server + "/dns-query?dns=" + query
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	//log.Println(b)
	//log.Println("use dns over https "+domain)

	return resolveAnswer(req, b)
}
