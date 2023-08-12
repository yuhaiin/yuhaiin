package simplehttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sort"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/latency"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (cc *HttpServerOption) GetConfig(w http.ResponseWriter, r *http.Request) error {
	return WhenNoError(cc.Config.Load(r.Context(), &emptypb.Empty{})).Do(func(t *config.Setting) error {
		w.Header().Set("Core-OS", runtime.GOOS)
		return MarshalProtoAndWrite(w, t, func(mo *protojson.MarshalOptions) { mo.EmitUnpopulated = true })
	})
}

func (c *HttpServerOption) SaveConfig(w http.ResponseWriter, r *http.Request) error {
	config := &config.Setting{}
	if err := UnmarshalProtoFromRequest(r, config); err != nil {
		return err
	}

	_, err := c.Config.Save(r.Context(), config)
	return err
}

func (g *HttpServerOption) GetGroups(w http.ResponseWriter, r *http.Request) error {
	group := r.URL.Query().Get("name")
	ns, err := g.NodeServer.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}
	z, ok := ns.GroupsV2[group]
	if !ok {
		return fmt.Errorf("can't find %s", group)
	}

	return MarshalJsonAndWrite(w, z.NodesV2)
}

func (g *HttpServerOption) GroupList(w http.ResponseWriter, r *http.Request) error {
	ns, err := g.NodeServer.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}
	groups := maps.Keys(ns.GroupsV2)
	sort.Strings(groups)

	return MarshalJsonAndWrite(w, groups)
}

func (t *HttpServerOption) TagList(w http.ResponseWriter, r *http.Request) error {
	m, err := t.NodeServer.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}

	type tag struct {
		Hash string `json:"hash"`
		Type string `json:"type"`
	}

	tags := make(map[string]tag)

	for k, v := range m.Tags {
		tags[k] = tag{
			Hash: v.GetHash()[0],
			Type: v.Type.String(),
		}
	}

	for _, v := range t.Shunt.Tags() {
		if _, ok := tags[v]; !ok {
			tags[v] = tag{}
		}
	}

	groups := make(map[string]map[string]string)

	for k, v := range m.GroupsV2 {
		groups[k] = v.NodesV2
	}

	return MarshalJsonAndWrite(w, map[string]any{"tags": tags, "groups": groups})
}

func (t *HttpServerOption) SaveTag(w http.ResponseWriter, r *http.Request) error {
	z := make(map[string]string)
	if err := UnmarshalJsonFromRequest(r, &z); err != nil {
		return err
	}

	tYPE, ok := pt.Type_value[z["type"]]
	if !ok {
		return fmt.Errorf("unknown tag type: %v", z["type"])
	}

	_, err := t.Tag.Save(r.Context(), &gn.SaveTagReq{
		Tag:  z["tag"],
		Hash: z["hash"],
		Type: pt.Type(tYPE),
	})
	return err
}

func (t *HttpServerOption) DeleteTag(w http.ResponseWriter, r *http.Request) error {
	_, err := t.Tag.Remove(r.Context(), &wrapperspb.StringValue{Value: r.URL.Query().Get("tag")})
	return err
}

func (l *HttpServerOption) udp(r *http.Request) *latency.Request {
	hash := r.URL.Query().Get("hash")
	return &latency.Request{
		Id:   "udp",
		Hash: hash,
		Protocol: &latency.Protocol{
			Protocol: &latency.Protocol_DnsOverQuic{
				DnsOverQuic: &latency.DnsOverQuic{
					Host:         "dns.nextdns.io:853",
					TargetDomain: "www.google.com",
				},
			},
			// Protocol: &latency.Protocol_Dns{
			// 	Dns: &latency.Dns{
			// 		Host:         "8.8.8.8",
			// 		TargetDomain: "www.google.com",
			// 	},
			// },
		},
	}
}

func (l *HttpServerOption) tcp(r *http.Request) *latency.Request {
	hash := r.URL.Query().Get("hash")
	return &latency.Request{
		Id:   "tcp",
		Hash: hash,
		Protocol: &latency.Protocol{
			Protocol: &latency.Protocol_Http{
				Http: &latency.Http{
					Url: "https://clients3.google.com/generate_204",
				},
			},
		},
	}
}

func (l *HttpServerOption) GetLatency(w http.ResponseWriter, r *http.Request) error {
	t := r.URL.Query().Get("type")

	req := &latency.Requests{}
	if t == "tcp" {
		req.Requests = append(req.Requests, l.tcp(r))
	}

	if t == "udp" {
		req.Requests = append(req.Requests, l.udp(r))
	}

	lt, err := l.NodeServer.Latency(r.Context(), req)
	if err != nil {
		return err
	}

	var tt *durationpb.Duration
	if z, ok := lt.IdLatencyMap["tcp"]; ok {
		tt = z
	} else if z, ok := lt.IdLatencyMap["udp"]; ok {
		tt = z
	}

	if tt == nil || tt.AsDuration() == 0 {
		return errors.New("test latency timeout or can't connect")
	}

	w.Write([]byte(tt.AsDuration().String()))

	return nil
}

func (s *HttpServerOption) SaveLink(w http.ResponseWriter, r *http.Request) error {
	name := r.URL.Query().Get("name")
	link := r.URL.Query().Get("link")

	if name == "" || link == "" {
		return errors.New("name or link is empty")
	}

	_, err := s.Subscribe.Save(r.Context(), &gn.SaveLinkReq{
		Links: []*subscribe.Link{
			{
				Name: name,
				Url:  link,
			},
		},
	})
	return err
}

func (s *HttpServerOption) GetLinkList(w http.ResponseWriter, r *http.Request) error {
	links, err := s.Subscribe.Get(r.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	linksValue := maps.Values(links.Links)

	sort.Slice(linksValue, func(i, j int) bool { return linksValue[i].Name < linksValue[j].Name })

	return MarshalJsonAndWrite(w, linksValue)
}

func (s *HttpServerOption) DeleteLink(w http.ResponseWriter, r *http.Request) error {
	data := r.URL.Query().Get("links")
	if data == "" {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	var names []string

	if err := json.Unmarshal([]byte(data), &names); err != nil {
		return err
	}

	_, err := s.Subscribe.Remove(r.Context(), &gn.LinkReq{Names: names})
	if err != nil {
		return err
	}

	return nil
}

func (s *HttpServerOption) PatchLink(w http.ResponseWriter, r *http.Request) error {
	data := r.URL.Query().Get("links")
	if data == "" {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	var names []string
	if err := json.Unmarshal([]byte(data), &names); err != nil {
		return err
	}

	_, err := s.Subscribe.Update(r.Context(), &gn.LinkReq{Names: names})
	if err != nil {
		return err
	}

	return nil
}

func (z *HttpServerOption) NodeNow(w http.ResponseWriter, r *http.Request) error {
	point, err := z.NodeServer.Now(r.Context(), &gn.NowReq{Net: gn.NowReq_tcp})
	if err != nil {
		return err
	}
	tcpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		return err
	}

	point, err = z.NodeServer.Now(r.Context(), &gn.NowReq{Net: gn.NowReq_udp})
	if err != nil {
		return err
	}
	udpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		return err
	}

	return MarshalJsonAndWrite(w, map[string]string{"tcp": string(tcpData), "udp": string(udpData)})
}

var protocolsMapping = map[string]*protocol.Protocol{
	"simple":       {Protocol: &protocol.Protocol_Simple{Simple: &protocol.Simple{Tls: &protocol.TlsConfig{CaCert: [][]byte{{0x0, 0x01}}}}}},
	"none":         {Protocol: &protocol.Protocol_None{}},
	"websocket":    {Protocol: &protocol.Protocol_Websocket{Websocket: &protocol.Websocket{}}},
	"quic":         {Protocol: &protocol.Protocol_Quic{Quic: &protocol.Quic{Tls: &protocol.TlsConfig{CaCert: [][]byte{{0x0, 0x01}}}}}},
	"shadowsocks":  {Protocol: &protocol.Protocol_Shadowsocks{}},
	"obfshttp":     {Protocol: &protocol.Protocol_ObfsHttp{}},
	"shadowsocksr": {Protocol: &protocol.Protocol_Shadowsocksr{}},
	"vmess":        {Protocol: &protocol.Protocol_Vmess{}},
	"trojan":       {Protocol: &protocol.Protocol_Trojan{}},
	"socks5":       {Protocol: &protocol.Protocol_Socks5{}},
	"http":         {Protocol: &protocol.Protocol_Http{}},
	"direct":       {Protocol: &protocol.Protocol_Direct{}},
	"yuubinsya":    {Protocol: &protocol.Protocol_Yuubinsya{Yuubinsya: &protocol.Yuubinsya{}}},
}

func (nn *HttpServerOption) GetNode(w http.ResponseWriter, r *http.Request) error {
	page := r.URL.Query().Get("page")

	if page == "generate_template" {
		return nn.generateTemplates(w, r)
	}

	hash := r.URL.Query().Get("hash")

	n, err := nn.NodeServer.Get(r.Context(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return err
	}

	return MarshalProtoAndWrite(w, n, func(mo *protojson.MarshalOptions) { mo.EmitUnpopulated = true })
}

func (n *HttpServerOption) generateTemplates(w http.ResponseWriter, r *http.Request) error {
	node := &point.Point{
		Hash:      "",
		Name:      "new node",
		Group:     "template group",
		Origin:    point.Origin_manual,
		Protocols: []*protocol.Protocol{},
	}

	var protolos []string
	if err := json.Unmarshal([]byte(r.URL.Query().Get("protocols")), &protolos); err != nil {
		return err
	}

	for _, v := range protolos {
		node.Protocols = append(node.Protocols, protocolsMapping[v])
	}

	return MarshalProtoAndWrite(w, node, func(mo *protojson.MarshalOptions) { mo.EmitUnpopulated = true; mo.Indent = " " })
}

func (n *HttpServerOption) DeleteNOde(w http.ResponseWriter, r *http.Request) error {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		return errors.New("hash is empty")
	}

	_, err := n.NodeServer.Remove(r.Context(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return err
	}

	return nil
}

func (n *HttpServerOption) SaveNode(w http.ResponseWriter, r *http.Request) error {
	point := &point.Point{}
	if err := UnmarshalProtoFromRequest(r, point); err != nil {
		return err
	}
	if _, err := n.NodeServer.Save(r.Context(), point); err != nil {
		return err
	}

	_, err := w.Write([]byte("successful"))
	return err
}

func (n *HttpServerOption) AddNode(w http.ResponseWriter, r *http.Request) error {
	hash := r.URL.Query().Get("hash")
	net := r.URL.Query().Get("net")

	req := &gn.UseReq{Hash: hash}

	switch net {
	case "tcp":
		req.Tcp = true
	case "udp":
		req.Udp = true
	default:
		req.Tcp = true
		req.Udp = true
	}

	_, err := n.NodeServer.Use(r.Context(), req)
	if err != nil {
		return err
	}

	return nil
}
