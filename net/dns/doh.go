package dns

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DOH DNS over HTTPS
// https://tools.ietf.org/html/rfc8484
func DOH(server string, domain string) (DNS []net.IP, err error) {
	return dnsCommon(domain, func(data []byte) ([]byte, error) { return post(data, server) })
}

func get(dReq []byte, server string) (body []byte, err error) {
	query := strings.Replace(base64.URLEncoding.EncodeToString(dReq), "=", "", -1)
	urls := "https://" + server + "/dns-query?dns=" + query
	res, err := http.Get(urls)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return
}

// https://www.cnblogs.com/mafeng/p/7068837.html
func post(dReq []byte, server string) (body []byte, err error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader(dReq))
	if err != nil {
		return nil, fmt.Errorf("DOH:post() newReq -> %v", err)
	}
	urls, err := url.Parse("//" + server)
	if err != nil {
		return nil, fmt.Errorf("DOH:post() urlParse -> %v", err)
	}
	req.URL.Scheme = "https"
	req.URL.Host = urls.Host
	req.URL.Path = urls.Path + "/dns-query"
	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("content-type", "application/dns-message")
	req.ContentLength = int64(len(dReq))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DOH:post() req -> %v", err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("DOH:post() readBody -> %v", err)
	}
	return
}
