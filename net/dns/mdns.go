package dns

import (
	"errors"
	"fmt"
	mdns "github.com/miekg/dns"
	"net"
)

//from https://miek.nl/2014/august/16/go-dns-package/

func MDNS(server, domain string) (ip []net.IP, err error) {
	//config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	//if err != nil{
	//	log.Println(err)
	//	return
	//}
	c := new(mdns.Client)
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, server)
	if r == nil {
		return nil, err
	}
	if r.Rcode != mdns.RcodeSuccess {
		return nil, errors.New(fmt.Sprintf(" *** invalid answer name %s after MX query for %s\n", domain, domain))
	}
	// Stuff must be in the answer section
	for _, a := range r.Answer {
		switch a.(type) {
		case *mdns.A:
			ip = append(ip, a.(*mdns.A).A)
		case *mdns.AAAA:
			ip = append(ip, a.(*mdns.AAAA).AAAA)
		}
	}
	return ip, nil
}
