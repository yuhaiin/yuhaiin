package migrate

import (
	"encoding/base64"
	json "encoding/json/v2"
	"fmt"
	"strings"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/node/parser"
	schemanode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	runtimenode "github.com/Asutorufa/yuhaiin/pkg/node"
)

func init() {
	runtimenode.RegisterSubscriptionParsers(ParseLegacyShareURL, ParseLegacyYuhaiinURL)
}

func ParseLegacyShareURL(data []byte, group, typ string) (contractnode.Node, error) {
	link := &schemanode.Link{Name: group, Type: legacyLinkType(typ)}
	point, err := parser.ParseUrl(data, link)
	if err != nil {
		return contractnode.Node{}, err
	}
	point.SetOrigin(schemanode.Origin_remote)
	node, _, err := ConvertLegacyNode(point)
	return node, err
}

func ParseLegacyYuhaiinURL(raw string) (runtimenode.ParsedYuhaiinURL, error) {
	encoded := strings.TrimPrefix(raw, "yuhaiin://")
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return runtimenode.ParsedYuhaiinURL{}, err
	}
	yu := &schemanode.YuhaiinUrl{}
	if err := json.Unmarshal(data, yu); err != nil {
		return runtimenode.ParsedYuhaiinURL{}, err
	}
	if yu.GetName() == "" {
		yu.SetName("default")
	}
	out := runtimenode.ParsedYuhaiinURL{Name: yu.GetName()}
	switch yu.WhichUrl() {
	case schemanode.YuhaiinUrl_Points_case:
		out.Points = make([]contractnode.Node, 0, len(yu.GetPoints().GetPoints()))
		for _, point := range yu.GetPoints().GetPoints() {
			node, _, err := ConvertLegacyNode(point)
			if err == nil {
				out.Points = append(out.Points, node)
			}
		}
	case schemanode.YuhaiinUrl_Remote_case:
		out.Remote = ptrToPublish(ConvertLegacyPublish(yu.GetRemote().GetPublish().GetName(), yu.GetRemote().GetPublish()))
	default:
		return runtimenode.ParsedYuhaiinURL{}, fmt.Errorf("unknown yuhaiin url type")
	}
	return out, nil
}

func legacyLinkType(typ string) schemanode.Type {
	if value, ok := schemanode.Type_value[typ]; ok {
		return schemanode.Type(value)
	}
	return schemanode.Type_reserve
}

func ptrToPublish(in contractsubscription.Publish) *contractsubscription.Publish {
	return &in
}
