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

	"github.com/Asutorufa/yuhaiin/net/common"
)

var (
	Subnet = net.ParseIP("0.0.0.0")
)

// https://tools.ietf.org/html/rfc8484
func DOH(server string, domain string) (DNS []net.IP, err error) {
	//log.Println(server, domain)
	if x, _ := cache.Get(domain); x != nil {
		//log.Println("hit cache " + domain)
		return x.([]net.IP), nil
	}

	req := createEDNSReq(domain, A, createEdnsClientSubnet(Subnet))
	//req := creatRequest(domain, A)
	// log.Println(req)

	//no := time.Now()
	//fmt.Println("post start")
	var b = common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(b)
	b, err = post(req, server)
	if err != nil {
		//log.Println(err)
		return nil, err
	}
	//fmt.Println("post end", time.Since(no))
	//log.Println(b)
	//log.Println("use dns over https " + domain)

	// resolve answer
	h, c, err := resolveHeader(req, b)
	if err != nil {
		return nil, err
	}
	//log.Println(c, h.arCount, h.anCount, h.nsCount, h.qdCount)
	DNS, c, err = resolveAnswer(c, h.anCount, b)
	if len(DNS) > 0 {
		cache.Add(domain, DNS)
	}
	c = resolveAuthoritative(c, h.nsCount, b)
	resolveAdditional(c, h.arCount)
	return
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
		return nil, err
	}
	urls, err := url.Parse("//" + server)
	if err != nil {
		return nil, fmt.Errorf("DOH:func post() -> %v", err)
	}
	req.URL.Scheme = "https"
	req.URL.Host = urls.Host
	req.URL.Path = urls.Path + "/dns-query"
	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("content-type", "application/dns-message")
	req.ContentLength = int64(len(dReq))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return
}
