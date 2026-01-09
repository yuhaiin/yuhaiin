package api

import (
	"github.com/Asutorufa/yuhaiin/pkg/structs/node"
)

type NowResp struct {
	Tcp node.Point `json:"tcp"`
	Udp node.Point `json:"udp"`
}

type UseReq struct {
	Hash string `json:"hash"`
}

type NodesResponseNode struct {
	Hash string `json:"hash"`
	Name string `json:"name"`
}

type NodesResponseGroup struct {
	Name  string              `json:"name"`
	Nodes []NodesResponseNode `json:"nodes"`
}

type NodesResponse struct {
	Groups []NodesResponseGroup `json:"groups"`
}

type ActivatesResponse struct {
	Nodes []node.Point `json:"nodes"`
}

type Node struct {
	Now       Service[struct{}, NowResp]
	Use       Service[UseReq, node.Point]
	Get       Service[string, node.Point]
	Save      Service[node.Point, node.Point]
	Remove    Service[string, struct{}]
	List      Service[struct{}, NodesResponse]
	Activates Service[struct{}, ActivatesResponse]
	Close     Service[string, struct{}]
	Latency   Service[node.Requests, node.Response]
}

type SavePublishRequest struct {
	Name    string       `json:"name"`
	Publish node.Publish `json:"publish"`
}

type ListPublishResponse struct {
	Publishes map[string]node.Publish `json:"publishes"`
}

type PublishRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Path     string `json:"path"`
}

type PublishResponse struct {
	Points []node.Point `json:"points"`
}

type SaveLinkReq struct {
	Links []node.Link `json:"links"`
}

type LinkReq struct {
	Names []string `json:"names"`
}

type GetLinksResp struct {
	Links map[string]node.Link `json:"links"`
}

type Subscribe struct {
	Save          Service[SaveLinkReq, struct{}]
	Remove        Service[LinkReq, struct{}]
	Update        Service[LinkReq, struct{}]
	Get           Service[struct{}, GetLinksResp]
	RemovePublish Service[string, struct{}]
	ListPublish   Service[struct{}, ListPublishResponse]
	SavePublish   Service[SavePublishRequest, struct{}]
	Publish       Service[PublishRequest, PublishResponse]
}

type SaveTagReq struct {
	Tag  string       `json:"tag"`
	Type node.TagType `json:"type"`
	Hash string       `json:"hash"`
}

type TagsResponse struct {
	Tags map[string]node.Tags `json:"tags"`
}

type Tag struct {
	Save   Service[SaveTagReq, struct{}]
	Remove Service[string, struct{}]
	List   Service[struct{}, TagsResponse]
}
