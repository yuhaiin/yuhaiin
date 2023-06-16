package simplehttp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type nodeHandler struct {
	nm grpcnode.NodeServer
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

func (nn *nodeHandler) Get(w http.ResponseWriter, r *http.Request) error {
	page := r.URL.Query().Get("page")

	if page == "generate_template" {
		return nn.generateTemplates(w, r)
	}

	hash := r.URL.Query().Get("hash")

	n, err := nn.nm.Get(r.Context(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return err
	}

	data, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(n)
	if err != nil {
		return err
	}

	w.Write(data)
	return nil
}

func (n *nodeHandler) generateTemplates(w http.ResponseWriter, r *http.Request) error {
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

	resp, err := protojson.MarshalOptions{Indent: " ", EmitUnpopulated: true}.Marshal(node)
	if err != nil {
		return err
	}

	w.Write(resp)
	return nil
}

func (n *nodeHandler) Delete(w http.ResponseWriter, r *http.Request) error {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		return errors.New("hash is empty")
	}

	_, err := n.nm.Remove(r.Context(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return err
	}

	w.Write(nil)
	return nil
}

func (n *nodeHandler) Post(w http.ResponseWriter, r *http.Request) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	point := &point.Point{}
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, point)
	if err != nil {
		return err
	}

	_, err = n.nm.Save(r.Context(), point)
	if err != nil {
		return err
	}

	w.Write([]byte("successful"))
	return nil
}

func (n *nodeHandler) Put(w http.ResponseWriter, r *http.Request) error {
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

	w.Write(nil)
	return nil
}
