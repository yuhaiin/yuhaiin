package api

import (
	context "context"
	"fmt"
	"sort"

	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var _ NodeServer = (*Node)(nil)

type Node struct {
	UnimplementedNodeServer
	nodeManager subscr.NodeManagerServer
}

func NewNode(e subscr.NodeManagerServer) NodeServer {
	return &Node{nodeManager: e}
}

func (n *Node) GetNodes(context.Context, *emptypb.Empty) (*Nodes, error) {
	nodes := &Nodes{Value: map[string]*AllGroupOrNode{}}

	nn, err := n.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return &Nodes{}, nil
	}

	for k, v := range nn.GroupNodesMap {
		sort.Strings(v.Nodes)
		nodes.Value[k] = &AllGroupOrNode{Value: v.Nodes}
	}

	return nodes, nil
}

func (n *Node) GetGroup(context.Context, *emptypb.Empty) (*AllGroupOrNode, error) {
	z, err := n.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return nil, fmt.Errorf("get nodes failed: %v", err)
	}
	return &AllGroupOrNode{Value: z.Groups}, err
}

func (n *Node) GetNode(_ context.Context, req *wrapperspb.StringValue) (*AllGroupOrNode, error) {
	nn, err := n.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return nil, fmt.Errorf("get nodes failed: %v", err)
	}

	g, ok := nn.GroupNodesMap[req.Value]
	if !ok {
		return nil, fmt.Errorf("group %v is not exist", req.Value)
	}

	return &AllGroupOrNode{Value: g.Nodes}, err
}

func (n *Node) GetNowGroupAndName(context.Context, *emptypb.Empty) (*GroupAndNode, error) {
	p, err := n.nodeManager.Now(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return &GroupAndNode{}, nil
	}
	return &GroupAndNode{Node: p.NName, Group: p.NGroup}, nil
}

func (n *Node) AddNode(_ context.Context, req *NodeMap) (*emptypb.Empty, error) {
	// TODO add node
	return &emptypb.Empty{}, nil
}

func (n *Node) ModifyNode(context.Context, *NodeMap) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (n *Node) DeleteNode(_ context.Context, req *GroupAndNode) (*emptypb.Empty, error) {
	hash, err := n.getHash(req.Group, req.Node)
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("get hash failed: %v", err)
	}
	return n.nodeManager.DeleteNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
}

func (n *Node) ChangeNowNode(_ context.Context, req *GroupAndNode) (*emptypb.Empty, error) {
	hash, err := n.getHash(req.Group, req.Node)
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("get hash failed: %v", err)
	}
	_, err = n.nodeManager.ChangeNowNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("change now node failed: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func (n *Node) Latency(_ context.Context, req *GroupAndNode) (*wrapperspb.StringValue, error) {
	hash, err := n.getHash(req.Group, req.Node)
	if err != nil {
		return &wrapperspb.StringValue{Value: err.Error()}, err
	}
	return n.nodeManager.Latency(context.TODO(), &wrapperspb.StringValue{Value: hash})
}

func (n *Node) getHash(group, name string) (string, error) {
	nn, err := n.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return "", fmt.Errorf("get nodes failed: %v", err)
	}
	g, ok := nn.GroupNodesMap[group]
	if !ok {
		return "", fmt.Errorf("group %v is not exist", group)
	}

	nnn, ok := g.NodeHashMap[name]
	if !ok {
		return "", fmt.Errorf("node %v is not exist", name)
	}

	return nnn, nil
}
