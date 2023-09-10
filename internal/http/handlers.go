package simplehttp

import (
	"net/http"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/latency"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (cc *HttpServerOption) GetConfig(w http.ResponseWriter, r *http.Request) error {
	return WhenNoError(cc.Config.Load(r.Context(), &emptypb.Empty{})).Do(func(t *config.Setting) error {
		w.Header().Set("Core-OS", runtime.GOOS)
		return MarshalProtoAndWrite(w, t)
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

func (t *HttpServerOption) Manager(w http.ResponseWriter, r *http.Request) error {
	m, err := t.NodeServer.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}

	for _, v := range t.Shunt.Tags() {
		if _, ok := m.Tags[v]; !ok {
			if m.Tags == nil {
				m.Tags = map[string]*pt.Tags{}
			}
			m.Tags[v] = &pt.Tags{}
		}
	}

	return MarshalProtoAndWrite(w, m)
}

func (t *HttpServerOption) SaveTag(w http.ResponseWriter, r *http.Request) error {
	var req gn.SaveTagReq
	if err := UnmarshalProtoFromRequest(r, &req); err != nil {
		return err
	}

	_, err := t.Tag.Save(r.Context(), &req)
	return err
}

func (t *HttpServerOption) DeleteTag(w http.ResponseWriter, r *http.Request) error {
	_, err := t.Tag.Remove(r.Context(), &wrapperspb.StringValue{Value: r.URL.Query().Get("tag")})
	return err
}

func (l *HttpServerOption) GetLatency(w http.ResponseWriter, r *http.Request) error {
	req := &latency.Requests{}
	if err := UnmarshalProtoFromRequest(r, req); err != nil {
		return err
	}

	lt, err := l.NodeServer.Latency(r.Context(), req)
	if err != nil {
		return err
	}

	return MarshalProtoAndWrite(w, lt)
}

func (s *HttpServerOption) SaveLink(w http.ResponseWriter, r *http.Request) error {
	var req gn.SaveLinkReq
	if err := UnmarshalProtoFromRequest(r, &req); err != nil {
		return err
	}

	_, err := s.Subscribe.Save(r.Context(), &req)
	return err
}

func (s *HttpServerOption) GetLinkList(w http.ResponseWriter, r *http.Request) error {
	links, err := s.Subscribe.Get(r.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	return MarshalProtoAndWrite(w, links)
}

func (s *HttpServerOption) DeleteLink(w http.ResponseWriter, r *http.Request) error {
	var req gn.LinkReq
	if err := UnmarshalProtoFromRequest(r, &req); err != nil {
		return err
	}

	_, err := s.Subscribe.Remove(r.Context(), &req)
	return err
}

func (s *HttpServerOption) PatchLink(w http.ResponseWriter, r *http.Request) error {
	var req gn.LinkReq
	if err := UnmarshalProtoFromRequest(r, &req); err != nil {
		return err
	}

	_, err := s.Subscribe.Update(r.Context(), &req)
	return err
}

func (z *HttpServerOption) NodeNow(w http.ResponseWriter, r *http.Request) error {
	now, err := z.NodeServer.Now(r.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	return MarshalProtoAndWrite(w, now)
}

func (nn *HttpServerOption) GetNode(w http.ResponseWriter, r *http.Request) error {
	req := &wrapperspb.StringValue{}
	if err := UnmarshalProtoFromRequest(r, req); err != nil {
		return err
	}
	n, err := nn.NodeServer.Get(r.Context(), req)
	if err != nil {
		return err
	}
	return MarshalProtoAndWrite(w, n)
}

func (n *HttpServerOption) DeleteNode(w http.ResponseWriter, r *http.Request) error {
	req := &wrapperspb.StringValue{}
	if err := UnmarshalProtoFromRequest(r, req); err != nil {
		return err
	}
	_, err := n.NodeServer.Remove(r.Context(), req)
	return err
}

func (n *HttpServerOption) SaveNode(w http.ResponseWriter, r *http.Request) error {
	point := &point.Point{}
	if err := UnmarshalProtoFromRequest(r, point); err != nil {
		return err
	}

	_, err := n.NodeServer.Save(r.Context(), point)
	return err
}

func (n *HttpServerOption) UseNode(w http.ResponseWriter, r *http.Request) error {
	var req gn.UseReq
	if err := UnmarshalProtoFromRequest(r, &req); err != nil {
		return err
	}

	_, err := n.NodeServer.Use(r.Context(), &req)
	return err
}

func (n *HttpServerOption) SaveBypass(w http.ResponseWriter, r *http.Request) error {
	req := &wrapperspb.StringValue{}
	if err := UnmarshalProtoFromRequest(r, req); err != nil {
		return err
	}
	_, err := n.Tools.SaveRemoteBypassFile(r.Context(), req)
	return err
}
