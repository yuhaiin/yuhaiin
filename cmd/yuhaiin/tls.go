package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
)

func loadManagementTLSCertificate(dataDir, certificatePath, privateKeyPath, names string) (tls.Certificate, string, bool, error) {
	if certificatePath == "" && privateKeyPath == "" {
		return managementtls.LoadOrCreate(dataDir, splitCertificateNames(names))
	}
	if certificatePath == "" || privateKeyPath == "" {
		return tls.Certificate{}, "", false, errors.New("-https-cert and -https-key must be used together")
	}
	certificate, fingerprint, err := managementtls.LoadPair(certificatePath, privateKeyPath)
	return certificate, fingerprint, false, err
}

func splitCertificateNames(value string) []string {
	var names []string
	for name := range strings.SplitSeq(value, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func redirectRemoteHTTPToHTTPS(handler http.Handler, httpsAddress net.Addr) http.Handler {
	_, tlsPort, err := net.SplitHostPort(httpsAddress.String())
	if err != nil {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil || isLoopbackPeer(r.RemoteAddr) || (r.Method != http.MethodGet && r.Method != http.MethodHead) ||
			strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/debug/") || r.URL.Path == "/metrics" {
			handler.ServeHTTP(w, r)
			return
		}
		host, ok := hostWithoutPort(r.Host)
		if !ok {
			handler.ServeHTTP(w, r)
			return
		}
		target := r.URL.Clone()
		target.Scheme = "https"
		target.Host = net.JoinHostPort(host, tlsPort)
		http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
	})
}

func hostWithoutPort(authority string) (string, bool) {
	if authority == "" {
		return "", false
	}
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return host, host != ""
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
		return host, host != ""
	}
	if strings.Count(authority, ":") > 1 {
		if ip := net.ParseIP(authority); ip != nil {
			return ip.String(), true
		}
		return "", false
	}
	return authority, true
}

func isLoopbackPeer(remoteAddress string) bool {
	peer, err := netip.ParseAddrPort(remoteAddress)
	return err == nil && peer.Addr().Unmap().IsLoopback()
}

func managementHTTPSURLs(address net.Addr) []string {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok {
		return nil
	}

	hosts := make(map[string]struct{})
	if tcpAddress.IP == nil || tcpAddress.IP.IsUnspecified() {
		hosts["localhost"] = struct{}{}
		if addresses, err := net.InterfaceAddrs(); err == nil {
			for _, address := range addresses {
				var ip net.IP
				switch value := address.(type) {
				case *net.IPNet:
					ip = value.IP
				case *net.IPAddr:
					ip = value.IP
				}
				if ip != nil && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
					hosts[ip.String()] = struct{}{}
				}
			}
		} else {
			hosts["127.0.0.1"] = struct{}{}
		}
	} else {
		hosts[tcpAddress.IP.String()] = struct{}{}
		if tcpAddress.IP.IsLoopback() {
			hosts["localhost"] = struct{}{}
		}
	}

	sortedHosts := make([]string, 0, len(hosts))
	for host := range hosts {
		sortedHosts = append(sortedHosts, host)
	}
	slices.Sort(sortedHosts)
	urls := make([]string, 0, len(sortedHosts))
	for _, host := range sortedHosts {
		urls = append(urls, (&url.URL{Scheme: "https", Host: net.JoinHostPort(host, strconv.Itoa(tcpAddress.Port))}).String())
	}
	return urls
}
