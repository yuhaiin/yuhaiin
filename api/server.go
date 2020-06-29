package api

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/process/process"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
)

type Server struct {
	UnimplementedApiServer
	Host string
}

var (
	message   chan string
	messageOn bool
)

func (s *Server) ProcessInit(context.Context, *empty.Empty) (*wrappers.StringValue, error) {
	err := process.GetProcessLock(s.Host)
	if err != nil {
		s, err := process.ReadLockFile()
		if err != nil {
			return &wrappers.StringValue{}, err
		}
		str := &wrappers.StringValue{Value: s}
		return str, nil
	}
	str := &wrappers.StringValue{Value: ""}
	return str, nil
}

func (s *Server) ClientOn(context.Context, *empty.Empty) (*empty.Empty, error) {
	if !messageOn {
		return &empty.Empty{}, errors.New("no client")
	}
	message <- "on"
	return &empty.Empty{}, nil
}

func (s *Server) ProcessExit(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.LockFileClose()
}

func (s *Server) GetConfig(context.Context, *empty.Empty) (*Setting, error) {
	conf, err := process.GetConfig()
	return reTrans(conf), err
}

func (s *Server) SetConfig(_ context.Context, req *Setting) (*empty.Empty, error) {
	return &empty.Empty{}, process.SetConFig(trans(req), false)
}

func (s *Server) ReimportRule(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.MatchCon.UpdateMatch()
}

func (s *Server) GetGroup(context.Context, *empty.Empty) (*AllGroupOrNode, error) {
	groups, err := process.GetGroups()
	return &AllGroupOrNode{Value: groups}, err
}

func (s *Server) GetNode(_ context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	nodes, err := process.GetNodes(req.Value)
	return &AllGroupOrNode{Value: nodes}, err
}

func (s *Server) GetNowGroupAndName(context.Context, *empty.Empty) (*NowNodeGroupAndNode, error) {
	node, group := process.GetNNodeAndNGroup()
	return &NowNodeGroupAndNode{Node: node, Group: group}, nil
}

func (s *Server) ChangeNowNode(_ context.Context, req *NowNodeGroupAndNode) (*empty.Empty, error) {
	return &empty.Empty{}, process.ChangeNNode(req.Group, req.Node)
}

func (s *Server) UpdateSub(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.UpdateSub()
}

func (s *Server) GetSubLinks(context.Context, *empty.Empty) (*AllGroupOrNode, error) {
	links, err := process.GetLinks()
	return &AllGroupOrNode{Value: links}, err
}

func (s *Server) AddSubLink(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	err := process.AddLink(req.Value)
	if err != nil {
		return nil, fmt.Errorf("api:AddSubLink -> %v", err)
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Server) DeleteSubLink(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	err := process.DeleteLink(req.Value)
	if err != nil {
		return nil, err
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Server) Latency(_ context.Context, req *NowNodeGroupAndNode) (*wrappers.StringValue, error) {
	latency, err := process.Latency(req.Group, req.Node)
	if err != nil {
		return nil, err
	}
	return &wrappers.StringValue{Value: latency.String()}, err
}

func (s *Server) GetAllDownAndUP(context.Context, *empty.Empty) (*DownAndUP, error) {
	dau := &DownAndUP{}
	dau.Download = common.DownloadTotal
	dau.Upload = common.UploadTotal
	return dau, nil
}

func (s *Server) ReducedUnit(_ context.Context, req *wrappers.DoubleValue) (*wrappers.StringValue, error) {
	return &wrappers.StringValue{Value: common.ReducedUnitStr(req.Value)}, nil
}

func (s *Server) SingleInstance(srv Api_SingleInstanceServer) error {
	if messageOn {
		return errors.New("already exist one client")
	}
	message = make(chan string, 1)
	messageOn = true
	ctx := srv.Context()

	for {
		select {
		case m := <-message:
			err := srv.Send(&wrappers.StringValue{Value: m})
			if err != nil {
				log.Println(err)
			}
		case <-ctx.Done():
			close(message)
			messageOn = false
			return ctx.Err()
		}
	}
}

func trans(i *Setting) *config.Setting {
	return iTrans(i).(*config.Setting)
}

func reTrans(i *config.Setting) *Setting {
	return iTrans(i).(*Setting)
}

func iTrans(ii interface{}) interface{} {
	switch ii.(type) {
	case *config.Setting:
		x := &Setting{}
		i := ii.(*config.Setting)
		x.BlackIcon = i.BlackIcon
		x.SsrPath = i.SsrPath
		x.RedirProxyAddress = i.RedirProxyAddress
		x.Socks5ProxyAddress = i.Socks5ProxyAddress
		x.HttpProxyAddress = i.HttpProxyAddress
		x.Bypass = i.Bypass
		x.BypassFile = i.BypassFile
		x.DnsServer = i.DnsServer
		x.DnsSubNet = i.DnsSubNet
		x.DNSAcrossProxy = i.DNSAcrossProxy
		x.IsDNSOverHTTPS = i.IsDNSOverHTTPS
		return x
	case *Setting:
		x := &config.Setting{}
		i := ii.(*Setting)
		x.BlackIcon = i.BlackIcon
		x.SsrPath = i.SsrPath
		x.RedirProxyAddress = i.RedirProxyAddress
		x.Socks5ProxyAddress = i.Socks5ProxyAddress
		x.HttpProxyAddress = i.HttpProxyAddress
		x.Bypass = i.Bypass
		x.BypassFile = i.BypassFile
		x.DnsServer = i.DnsServer
		x.DnsSubNet = i.DnsSubNet
		x.DNSAcrossProxy = i.DNSAcrossProxy
		x.IsDNSOverHTTPS = i.IsDNSOverHTTPS
		return x
	}
	return nil
}
