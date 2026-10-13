package node

import (
	"cmp"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"uuid"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

// PreviewImport parses without persisting. Imported nodes receive fresh identities,
// with references between nodes in the same batch rewritten to those identities.
func PreviewImport(request contractnode.ImportRequest) (contractnode.ImportPreview, error) {
	text := strings.TrimSpace(strings.TrimPrefix(request.Text, "\ufeff"))
	if text == "" || len(text) > 4<<20 {
		return contractnode.ImportPreview{}, errors.New("import must contain between 1 byte and 4 MiB")
	}
	group := cmp.Or(strings.TrimSpace(request.Group), "manual")
	result := contractnode.ImportPreview{Items: []contractnode.Node{}, Errors: []contractnode.ImportIssue{}}
	identities := map[string]string{}
	appendNode := func(value contractnode.Node, line int) {
		original := value.ID
		if original != "" {
			if _, exists := identities[original]; exists {
				result.Errors = append(result.Errors, contractnode.ImportIssue{Line: line, Message: "duplicate node ID in import"})
				return
			}
		}
		value.ID = uuid.New().String()
		value.Group = cmp.Or(value.Group, group)
		value.Origin = "manual"
		if err := value.Validate(); err != nil {
			result.Errors = append(result.Errors, contractnode.ImportIssue{Line: line, Message: err.Error()})
			return
		}
		if original != "" {
			identities[original] = value.ID
		}
		result.Items = append(result.Items, value)
	}
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		var raw []jsontext.Value
		if strings.HasPrefix(text, "[") {
			if err := json.Unmarshal([]byte(text), &raw); err != nil {
				return result, fmt.Errorf("invalid node JSON: %w", err)
			}
		} else {
			var envelope struct {
				Items []jsontext.Value `json:"items"`
			}
			if err := json.Unmarshal([]byte(text), &envelope); err != nil {
				return result, fmt.Errorf("invalid node JSON: %w", err)
			}
			if envelope.Items != nil {
				raw = envelope.Items
			} else {
				raw = []jsontext.Value{jsontext.Value(text)}
			}
		}
		for index, data := range raw {
			value := contractnode.Node{Enabled: true}
			if err := json.Unmarshal(data, &value); err != nil {
				result.Errors = append(result.Errors, contractnode.ImportIssue{Line: index + 1, Message: "invalid node JSON"})
				continue
			}
			appendNode(value, index+1)
		}
	} else {
		if decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), "")); err == nil {
			text = string(decoded)
		} else if decoded, err := base64.RawStdEncoding.DecodeString(strings.Join(strings.Fields(text), "")); err == nil {
			text = string(decoded)
		}
		line := 0
		for raw := range strings.SplitSeq(text, "\n") {
			line++
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if strings.HasPrefix(raw, "yuhaiin://") && subscriptionParsers.parseYuhaiinURL != nil {
				parsed, err := subscriptionParsers.parseYuhaiinURL(raw)
				if err != nil {
					result.Errors = append(result.Errors, contractnode.ImportIssue{Line: line, Message: "invalid yuhaiin link"})
					continue
				}
				if len(parsed.Points) == 0 {
					result.Errors = append(result.Errors, contractnode.ImportIssue{Line: line, Message: "this link is a subscription; add it as a subscription"})
					continue
				}
				for _, value := range parsed.Points {
					appendNode(value, line)
				}
				continue
			}
			if subscriptionParsers.parseShareURL == nil {
				return result, errors.New("node link parser is unavailable")
			}
			value, err := subscriptionParsers.parseShareURL([]byte(raw), group, "reserve")
			if err != nil {
				// Do not echo URLs containing passwords or tokens in error messages.
				result.Errors = append(result.Errors, contractnode.ImportIssue{Line: line, Message: "unsupported or invalid node link"})
				continue
			}
			value.Enabled = true
			appendNode(value, line)
		}
	}
	for index := range result.Items {
		for step := range result.Items[index].Chain {
			remapImportProtocol(&result.Items[index].Chain[step], identities)
		}
	}
	if len(result.Items) == 0 && len(result.Errors) == 0 {
		return result, errors.New("no nodes found")
	}
	return result, nil
}

func remapImportProtocol(protocol *contractnode.Protocol, identities map[string]string) {
	remap := func(id *string) {
		if replacement, ok := identities[*id]; ok {
			*id = replacement
		}
	}
	if protocol.Set != nil {
		for index := range protocol.Set.Nodes {
			remap(&protocol.Set.Nodes[index])
		}
	}
	if protocol.PointAsEndpoint != nil {
		remap(&protocol.PointAsEndpoint.Hash)
	}
	if protocol.NetworkSplit != nil {
		if protocol.NetworkSplit.TCP != nil {
			remapImportProtocol(protocol.NetworkSplit.TCP, identities)
		}
		if protocol.NetworkSplit.UDP != nil {
			remapImportProtocol(protocol.NetworkSplit.UDP, identities)
		}
	}
}
