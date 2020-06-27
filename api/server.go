package api

import (
	context "context"

	"github.com/golang/protobuf/ptypes/wrappers"

	"github.com/Asutorufa/yuhaiin/process/process"

	config2 "github.com/Asutorufa/yuhaiin/config"

	"github.com/golang/protobuf/ptypes/empty"
)

type server struct {
	UnimplementedApiServer
}

//message config{
//bool BlackIcon = 1;
//bool DOH = 2;
//bool DNSProxy = 3;
//string DNS = 4;
//string DNSSubNet = 5;
//bool Bypass = 6;
//string BypassFile = 7;
//string HTTP = 8;
//string SOCKS5 = 9;
//string REDIR = 10;
//string SSRPath = 11;
//}
func (s *server) SetConfig(ctx context.Context, req *Config) (*empty.Empty, error) {
	config := &config2.Setting{}
	config.BlackIcon = req.BlackIcon
	config.IsDNSOverHTTPS = req.DOH
	config.DNSAcrossProxy = req.DNSProxy
	config.DnsServer = req.DNS
	config.DnsSubNet = req.DNSSubNet
	config.Bypass = req.Bypass
	config.BypassFile = req.BypassFile
	config.HttpProxyAddress = req.HTTP
	config.Socks5ProxyAddress = req.SOCKS5
	config.RedirProxyAddress = req.REDIR
	config.SsrPath = req.SSRPath
	err := process.SetConFig(config, false)
	return nil, err
}

func (s *server) GetGroup(ctx context.Context, req *empty.Empty) (*AllGroupOrNode, error) {
	groups, err := process.GetGroups()
	return &AllGroupOrNode{Name: groups}, err
}

func (s *server) GetNode(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	nodes, err := process.GetNodes(req.Value)
	return &AllGroupOrNode{Name: nodes}, err
}

func (s *server) GetNowGroupAndName(ctx context.Context, req *empty.Empty) (*NowNodeGroupAndNode, error) {
	node, group := process.GetNNodeAndNGroup()
	return &NowNodeGroupAndNode{Node: node, Group: group}, nil
}

func (s *server) ChangeNowNode(ctx context.Context, req *NowNodeGroupAndNode) (*empty.Empty, error) {
	return nil, process.ChangeNNode(req.Group, req.Node)
}

func (s *server) Latency(ctx context.Context, req *NowNodeGroupAndNode) (*wrappers.StringValue, error) {
	latency, err := process.Latency(req.Group, req.Node)
	if err != nil {
		return nil, err
	}
	return &wrappers.StringValue{Value: latency.String()}, err
}
