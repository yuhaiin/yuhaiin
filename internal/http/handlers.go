package simplehttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sort"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	grpcconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	snode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/latency"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type HandlerImpl struct {
	cf  grpcconfig.ConfigServiceServer
	nm  snode.NodeServer
	ts  snode.TagServer
	st  *shunt.Shunt
	sb  grpcnode.SubscribeServer
	stt gs.ConnectionsServer
}

func (cc *HandlerImpl) Config(w http.ResponseWriter, r *http.Request) error {
	c, err := cc.cf.Load(r.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	w.Header().Set("Core-OS", runtime.GOOS)
	return MarshalProtoAndWrite(w, c, func(mo *protojson.MarshalOptions) { mo.EmitUnpopulated = true })
}

func (c *HandlerImpl) Post(w http.ResponseWriter, r *http.Request) error {
	config := &config.Setting{}
	if err := UnmarshalProtoFromRequest(r, config); err != nil {
		return err
	}

	if _, err := c.cf.Save(r.Context(), config); err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (g *HandlerImpl) Groups(w http.ResponseWriter, r *http.Request) error {
	group := r.URL.Query().Get("name")
	ns, err := g.nm.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}
	z, ok := ns.GroupsV2[group]
	if !ok {
		return fmt.Errorf("can't find %s", group)
	}

	return MarshalJsonAndWrite(w, z.NodesV2)
}

func (g *HandlerImpl) GroupList(w http.ResponseWriter, r *http.Request) error {
	ns, err := g.nm.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}
	groups := maps.Keys(ns.GroupsV2)
	sort.Strings(groups)

	return MarshalJsonAndWrite(w, groups)
}

func (t *HandlerImpl) TagList(w http.ResponseWriter, r *http.Request) error {
	m, err := t.nm.Manager(r.Context(), &wrapperspb.StringValue{})
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

	for _, v := range t.st.Tags() {
		if _, ok := tags[v]; !ok {
			tags[v] = tag{}
		}
	}

	groups := make(map[string]map[string]string)

	for k, v := range m.GroupsV2 {
		groups[k] = v.NodesV2
	}

	return MarshalJsonAndWrite(w, map[string]any{
		"tags":   tags,
		"groups": groups,
	})
}

func (t *HandlerImpl) SaveTag(w http.ResponseWriter, r *http.Request) error {
	z := make(map[string]string)
	if err := UnmarshalJsonFromRequest(r, &z); err != nil {
		return err
	}

	tYPE, ok := pt.Type_value[z["type"]]
	if !ok {
		return fmt.Errorf("unknown tag type: %v", z["type"])
	}

	_, err := t.ts.Save(r.Context(), &snode.SaveTagReq{
		Tag:  z["tag"],
		Hash: z["hash"],
		Type: pt.Type(tYPE),
	})
	return err
}

func (t *HandlerImpl) DeleteTag(w http.ResponseWriter, r *http.Request) error {
	_, err := t.ts.Remove(r.Context(), &wrapperspb.StringValue{Value: r.URL.Query().Get("tag")})
	return err
}

func (l *HandlerImpl) udp(r *http.Request) *latency.Request {
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

func (l *HandlerImpl) tcp(r *http.Request) *latency.Request {
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

func (l *HandlerImpl) Get(w http.ResponseWriter, r *http.Request) error {
	t := r.URL.Query().Get("type")

	req := &latency.Requests{}
	if t == "tcp" {
		req.Requests = append(req.Requests, l.tcp(r))
	}

	if t == "udp" {
		req.Requests = append(req.Requests, l.udp(r))
	}

	lt, err := l.nm.Latency(r.Context(), req)
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

func (s *HandlerImpl) SaveLink(w http.ResponseWriter, r *http.Request) error {
	name := r.URL.Query().Get("name")
	link := r.URL.Query().Get("link")

	if name == "" || link == "" {
		return errors.New("name or link is empty")
	}

	_, err := s.sb.Save(r.Context(), &grpcnode.SaveLinkReq{
		Links: []*subscribe.Link{
			{
				Name: name,
				Url:  link,
			},
		},
	})
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *HandlerImpl) GetLinkList(w http.ResponseWriter, r *http.Request) error {
	links, err := s.sb.Get(r.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	linksValue := maps.Values(links.Links)

	sort.Slice(linksValue, func(i, j int) bool { return linksValue[i].Name < linksValue[j].Name })

	return MarshalJsonAndWrite(w, linksValue)
}

func (s *HandlerImpl) DeleteLink(w http.ResponseWriter, r *http.Request) error {
	data := r.URL.Query().Get("links")
	if data == "" {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	var names []string

	if err := json.Unmarshal([]byte(data), &names); err != nil {
		return err
	}

	_, err := s.sb.Remove(r.Context(), &grpcnode.LinkReq{Names: names})
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *HandlerImpl) PatchLink(w http.ResponseWriter, r *http.Request) error {
	data := r.URL.Query().Get("links")
	if data == "" {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	var names []string
	if err := json.Unmarshal([]byte(data), &names); err != nil {
		return err
	}

	_, err := s.sb.Update(r.Context(), &grpcnode.LinkReq{Names: names})
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (z *HandlerImpl) NodeNow(w http.ResponseWriter, r *http.Request) error {
	point, err := z.nm.Now(r.Context(), &grpcnode.NowReq{Net: grpcnode.NowReq_tcp})
	if err != nil {
		return err
	}
	tcpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		return err
	}

	point, err = z.nm.Now(r.Context(), &grpcnode.NowReq{Net: grpcnode.NowReq_udp})
	if err != nil {
		return err
	}
	udpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		return err
	}

	data, err := json.Marshal(map[string]string{
		"tcp": string(tcpData),
		"udp": string(udpData),
	})
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
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
}

func (nn *HandlerImpl) GetNode(w http.ResponseWriter, r *http.Request) error {
	page := r.URL.Query().Get("page")

	if page == "generate_template" {
		return nn.generateTemplates(w, r)
	}

	hash := r.URL.Query().Get("hash")

	n, err := nn.nm.Get(r.Context(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return err
	}

	return MarshalProtoAndWrite(w, n, func(mo *protojson.MarshalOptions) { mo.EmitUnpopulated = true })
}

func (n *HandlerImpl) generateTemplates(w http.ResponseWriter, r *http.Request) error {
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

func (n *HandlerImpl) DeleteNOde(w http.ResponseWriter, r *http.Request) error {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		return errors.New("hash is empty")
	}

	_, err := n.nm.Remove(r.Context(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (n *HandlerImpl) SaveNode(w http.ResponseWriter, r *http.Request) error {
	point := &point.Point{}
	if err := UnmarshalProtoFromRequest(r, point); err != nil {
		return err
	}
	if _, err := n.nm.Save(r.Context(), point); err != nil {
		return err
	}

	_, err := w.Write([]byte("successful"))
	return err
}

func (n *HandlerImpl) AddNode(w http.ResponseWriter, r *http.Request) error {
	hash := r.URL.Query().Get("hash")
	net := r.URL.Query().Get("net")

	req := &grpcnode.UseReq{Hash: hash}

	switch net {
	case "tcp":
		req.Tcp = true
	case "udp":
		req.Udp = true
	default:
		req.Tcp = true
		req.Udp = true
	}

	_, err := n.nm.Use(r.Context(), req)
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	return nil
}
