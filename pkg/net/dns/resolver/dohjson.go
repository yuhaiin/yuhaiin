package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	EdnsClientSubnet string     `json:"edns_client_subnet"`
	Question         []Question `json:"Question"`
	Answer           []Answer   `json:"Answer"`
	Status           int        `json:"status"`
	TC               bool       `json:"TC"`
	RD               bool       `json:"RD"`
	RA               bool       `json:"RA"`
	AD               bool       `json:"AD"`
	CD               bool       `json:"CD"`
}
type Question struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}
type Answer struct {
	Name    string `json:"name"`
	Expires string `json:"Expires"`
	Data    string `json:"data"`
	Type    int    `json:"type"`
	TTL     int    `json:"TTL"`
}

func DOHJsonAPI(DNSServer, domain string, proxy func(ctx context.Context, network, addr string) (net.Conn, error)) (DNS *DOHJson, err error) {

	hc := &http.Client{}
	if proxy != nil {
		hc.Transport = &http.Transport{DialContext: proxy}
	}

	res, err := hc.Get(DNSServer + "?ct=application/dns-json&name=" + domain + "&type=A")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		data, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("status code: %d, data: %s", res.StatusCode, string(data))
	}

	doh := &DOHJson{}
	err = json.NewDecoder(res.Body).Decode(doh)
	if err != nil {
		return nil, err
	}

	if doh.Status != 0 {
		return nil, fmt.Errorf("dns status code: %d", doh.Status)
	}

	return doh, nil
}
