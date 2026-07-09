package migrate

import (
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	schemaapi "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/api"
	schemanode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
)

func ConvertLegacyLinks(in *schemaapi.GetLinksResp) contractsubscription.LinkList {
	var out contractsubscription.LinkList
	if in == nil {
		return out
	}
	out.Items = make([]contractsubscription.Link, 0, len(in.Links))
	for name, link := range in.Links {
		if link == nil {
			continue
		}
		out.Items = append(out.Items, contractsubscription.Link{
			Name: firstNonEmpty(link.GetName(), name),
			URL:  link.GetUrl(),
			Type: link.GetType().String(),
		})
	}
	return out
}

func ConvertContractLinks(in []contractsubscription.Link) []*schemanode.Link {
	out := make([]*schemanode.Link, 0, len(in))
	for _, link := range in {
		typ := schemanode.Type_reserve
		if v, ok := schemanode.Type_value[link.Type]; ok {
			typ = schemanode.Type(v)
		}
		out = append(out, &schemanode.Link{
			Name: link.Name,
			Url:  link.URL,
			Type: typ,
		})
	}
	return out
}

func ConvertLegacyPublishes(in *schemaapi.ListPublishResponse) contractsubscription.PublishList {
	var out contractsubscription.PublishList
	if in == nil {
		return out
	}
	out.Items = make([]contractsubscription.Publish, 0, len(in.Publishes))
	for name, publish := range in.Publishes {
		if publish == nil {
			continue
		}
		out.Items = append(out.Items, ConvertLegacyPublish(firstNonEmpty(publish.GetName(), name), publish))
	}
	return out
}

func ConvertLegacyPublish(name string, in *schemanode.Publish) contractsubscription.Publish {
	if in == nil {
		return contractsubscription.Publish{Name: name}
	}
	return contractsubscription.Publish{
		Name:     firstNonEmpty(in.GetName(), name),
		Points:   in.GetPoints(),
		Path:     in.GetPath(),
		Password: in.GetPassword(),
		Address:  in.GetAddress(),
		Insecure: in.GetInsecure(),
	}
}

func ConvertContractPublish(in contractsubscription.Publish) *schemanode.Publish {
	return &schemanode.Publish{
		Name:     in.Name,
		Points:   in.Points,
		Path:     in.Path,
		Password: in.Password,
		Address:  in.Address,
		Insecure: in.Insecure,
	}
}

func ConvertLegacyPublishResponse(in *schemaapi.PublishResponse) contractsubscription.ResolvePublishResponse {
	var out contractsubscription.ResolvePublishResponse
	if in == nil {
		return out
	}
	out.Points = make([]contractnode.Node, 0, len(in.GetPoints()))
	for _, point := range in.GetPoints() {
		node, _, err := ConvertLegacyNode(point)
		if err == nil {
			out.Points = append(out.Points, node)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
