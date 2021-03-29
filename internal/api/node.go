package api

import (
	context "context"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Node struct {
	UnimplementedNodeServer
	entrance *app.Entrance
}

func NewNode(e *app.Entrance) *Node {
	return &Node{
		entrance: e,
	}
}

func (n *Node) GetNodes(context.Context, *emptypb.Empty) (*Nodes, error) {
	nodes := &Nodes{Value: map[string]*AllGroupOrNode{}}
	nods := n.entrance.GetANodes()
	for key := range nods {
		nodes.Value[key] = &AllGroupOrNode{Value: nods[key]}
	}
	return nodes, nil
}

func (n *Node) GetGroup(context.Context, *emptypb.Empty) (*AllGroupOrNode, error) {
	groups, err := n.entrance.GetGroups()
	return &AllGroupOrNode{Value: groups}, err
}

func (n *Node) GetNode(_ context.Context, req *wrapperspb.StringValue) (*AllGroupOrNode, error) {
	nodes, err := n.entrance.GetNodes(req.Value)
	return &AllGroupOrNode{Value: nodes}, err
}

func (n *Node) GetNowGroupAndName(context.Context, *emptypb.Empty) (*GroupAndNode, error) {
	node, group := n.entrance.GetNNodeAndNGroup()
	return &GroupAndNode{Node: node, Group: group}, nil
}

func (n *Node) AddNode(_ context.Context, req *NodeMap) (*emptypb.Empty, error) {
	// TODO add node
	return &emptypb.Empty{}, nil
}

func (n *Node) ModifyNode(context.Context, *NodeMap) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (n *Node) DeleteNode(_ context.Context, req *GroupAndNode) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, n.entrance.DeleteNode(req.Group, req.Node)
}

func (n *Node) ChangeNowNode(_ context.Context, req *GroupAndNode) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, n.entrance.ChangeNNode(req.Group, req.Node)
}

func (n *Node) Latency(_ context.Context, req *GroupAndNode) (*wrapperspb.StringValue, error) {
	latency, err := n.entrance.Latency(req.Group, req.Node)
	if err != nil {
		return nil, err
	}
	return &wrapperspb.StringValue{Value: latency.String()}, err
}
