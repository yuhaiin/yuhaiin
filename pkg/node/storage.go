package node

import (
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

type NodeStore interface {
	SaveContractNode(contractnode.Node) error
	ReplaceRemoteContractNodes(group string, nodes []contractnode.Node) error
	DeleteNode(id string) error
	GetContractNode(id string) (contractnode.Node, bool, error)
	ListContractNodes() ([]contractnode.Node, error)
	GetContractNow(tcp bool) (contractnode.Node, bool, error)
	UsePoint(id string) error
	AddContractTag(tag, kind, target string) error
	DeleteTag(tag string) error
	GetContractTag(tag string) (string, []string, bool, error)
	UsingContractPoints() (*set.Set[string], error)
	Close() error
}
