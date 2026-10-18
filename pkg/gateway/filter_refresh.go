package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func (m *Manager) RefreshFilter(ctx context.Context, id string) (contract.Config, error) {
	config := m.Config()
	index := -1
	for n := range config.FilterLists {
		if config.FilterLists[n].ID == id {
			index = n
			break
		}
	}
	if index < 0 {
		return config, errors.New("filter list not found")
	}
	list := &config.FilterLists[index]
	u, err := url.Parse(list.URL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
		return config, errors.New("filter source must be an HTTP or HTTPS URL")
	}
	s := m.current.Load()
	g := s.gateways[list.GatewayID]
	if g == nil {
		return config, errors.New("filter gateway not found")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(netapi.WithContext(ctx), "GET", u.String(), nil)
	if err != nil {
		return config, err
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	address, err := netapi.ParseAddress("tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return config, err
	}
	selected, err := g.engine.selectOutbound(request.Context(), address, contract.Action{}.Outbound)
	if err != nil {
		return config, err
	}
	tr, release, err := g.engine.pool.borrow(selected, u.Scheme+"://"+u.Host, contract.Upstream{})
	if err != nil {
		return config, err
	}
	defer release()
	// RoundTrip deliberately does not follow redirects into an unrelated origin.
	response, err := tr.RoundTrip(request)
	if err != nil {
		return config, errors.New("filter source request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return config, errors.New("filter source must return HTTP 200 without a redirect")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		return config, err
	}
	if len(data) > 4<<20 {
		return config, errors.New("filter source exceeds 4 MiB")
	}
	list.Text = string(data)
	list.UpdatedAt = time.Now().UTC()
	parsed, err := CompileFilters([]contract.FilterList{*list})
	if err != nil {
		return config, err
	}
	if len(parsed.reports) == 0 || parsed.reports[0].Accepted == 0 {
		return config, errors.New("filter source contains no supported rules")
	}
	return m.Save(ctx, config)
}
