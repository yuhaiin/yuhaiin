package dns

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
)

/*
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "google.com.",
      "type": 1
    }
  ],
  "Answer": [
    {
      "name": "google.com.",
      "type": 1,
      "TTL": 252,
      "Expires": "Fri, 14 Feb 2020 09:53:44 UTC",
      "data": "172.217.31.238"
    }
  ],
  "edns_client_subnet": "110.166.218.0/0"
}

{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "baidu.com.",
      "type": 1
    }
  ],
  "Answer": [
    {
      "name": "baidu.com.",
      "type": 1,
      "TTL": 518,
      "Expires": "Fri, 14 Feb 2020 09:59:03 UTC",
      "data": "39.156.69.79"
    },
    {
      "name": "baidu.com.",
      "type": 1,
      "TTL": 518,
      "Expires": "Fri, 14 Feb 2020 09:59:03 UTC",
      "data": "220.181.38.148"
    }
  ],
  "edns_client_subnet": "110.166.218.0/0"
}
*/

type DOHJson struct {
	Status           int        `json:"status"`
	TC               bool       `json:"TC"`
	RD               bool       `json:"RD"`
	RA               bool       `json:"RA"`
	AD               bool       `json:"AD"`
	CD               bool       `json:"CD"`
	Question         []Question `json:"Question"`
	Answer           []Answer   `json:"Answer"`
	EdnsClientSubnet string     `json:"edns_client_subnet"`
}
type Question struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}
type Answer struct {
	Name    string `json:"name"`
	Type    int    `json:"type"`
	TTL     int    `json:"TTL"`
	Expires string `json:"Expires"`
	Data    string `json:"data"`
}

func DOHJsonAPI(DNSServer, domain string, proxy func(ctx context.Context, network, addr string) (net.Conn, error)) (DNS []net.IP, err error) {
	doh := &DOHJson{}
	var res *http.Response
	if proxy != nil {
		tr := http.Transport{
			DialContext: proxy,
		}
		newClient := &http.Client{Transport: &tr}
		res, err = newClient.Get(DNSServer + "?ct=application/dns-json&name=" + domain + "&type=A")
	} else {
		res, err = http.Get(DNSServer + "?ct=application/dns-json&name=" + domain + "&type=A")
	}
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, doh)
	if err != nil {
		return nil, err
	}
	if doh.Status != 0 {
		return nil, err
	}
	for _, x := range doh.Answer {
		if net.ParseIP(x.Data) != nil {
			DNS = append(DNS, net.ParseIP(x.Data))
		}
	}
	return DNS, nil
}
