package mcpserver

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"uuid"

	contractgateway "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

// Configuration tools create, change, delete and test configuration through
// the same HTTP API operations the Web UI uses. Their schemas are derived from
// the API request DTOs, the arguments are decoded strictly into those DTOs,
// and the operations apply their usual validation, secret handling and
// configuration audit.

type toolKind int

const (
	readTool toolKind = iota
	writeTool
	destructiveTool
	testTool
)

func (k toolKind) apply(t Tool) Tool {
	switch k {
	case readTool:
		t.ReadOnly, t.Idempotent = true, true
	case writeTool:
		t.Idempotent = true
	case destructiveTool:
		t.Destructive, t.Idempotent = true, true
	case testTool:
		t.ReadOnly, t.OpenWorld = true, true
	}
	return t
}

// strictDTO decodes MCP arguments into the operation's request type,
// rejecting unknown members, and re-encodes them for the operation.
func strictDTO[T any](normalize func(*T) error) func([]byte) ([]byte, error) {
	return func(raw []byte) ([]byte, error) {
		var value T
		if err := json.Unmarshal(raw, &value, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("arguments do not match the tool schema: %w", err)
		}
		if normalize != nil {
			if err := normalize(&value); err != nil {
				return nil, err
			}
		}
		return json.Marshal(value)
	}
}

func dtoTool[T any](kind toolKind, name, title, operation, description string, normalize func(*T) error) Tool {
	return kind.apply(Tool{Name: name, Title: title, Operation: operation, Description: description, Schema: schemaFor[T](), Arguments: strictDTO(normalize)})
}

type idArguments struct {
	ID string `json:"id"`
}

func requireID(value *idArguments) error {
	if strings.TrimSpace(value.ID) == "" || len(value.ID) > 256 {
		return errors.New("id is required")
	}
	return nil
}

func idTool(kind toolKind, name, title, operation, description string) Tool {
	t := dtoTool(kind, name, title, operation, description, requireID)
	t.Schema = object(map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}}, "id")
	return t
}

// newID fills an empty identifier for a new object, as the Web UI does.
func newID(id *string) {
	if strings.TrimSpace(*id) == "" {
		*id = uuid.New().String()
	}
}

type hostArguments struct {
	Host string `json:"host"`
}

type routeListUpdate struct {
	ID string `json:"id"`
	contractroute.RouteListDetail
}

type routeRuleUpdate struct {
	ID string `json:"id"`
	contractroute.RuleDraft
}

type nodeLatencyArguments struct {
	ID string `json:"id"`
	contractnode.LatencyRequest
}

type nodeImportArguments struct {
	Text    string `json:"text"`
	Group   string `json:"group"`
	Indices []int  `json:"indices,omitzero"`
}

func validImport(value *nodeImportArguments) error {
	if strings.TrimSpace(value.Text) == "" || len(value.Text) > 1<<20 || len(value.Group) > 256 || len(value.Indices) > 1000 {
		return errors.New("text with share links or a subscription body is required (at most 1 MiB)")
	}
	return nil
}

// importNodes previews share links, assigns fresh IDs and commits the chosen
// entries, composing the two import operations the Web UI uses.
func importNodes(ctx context.Context, invoke Invoker, body []byte) (any, error) {
	var args nodeImportArguments
	if err := json.Unmarshal(body, &args); err != nil {
		return nil, err
	}
	preview, err := invoke(ctx, "nodes.import.preview", body)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(preview)
	if err != nil {
		return nil, err
	}
	var parsed contractnode.ImportPreview
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Items) == 0 {
		return map[string]any{"saved": 0, "errors": parsed.Errors}, nil
	}
	commit := contractnode.ImportCommit{Text: args.Text, Group: args.Group, Indices: args.Indices}
	for range parsed.Items {
		commit.IDs = append(commit.IDs, uuid.New().String())
	}
	request, err := json.Marshal(commit)
	if err != nil {
		return nil, err
	}
	result, err := invoke(ctx, "nodes.import.commit", request)
	if err != nil {
		return nil, err
	}
	return map[string]any{"results": result, "parseErrors": parsed.Errors}, nil
}

func configurationTools() []Tool {
	importTool := dtoTool(writeTool, "import_nodes", "Import nodes", "nodes.import.commit",
		"Adds nodes from share links (ss://, vmess://, trojan://, vless://, hysteria2:// and others, one per line) or a subscription body. Optional indices select entries of preview_node_import; all entries are imported otherwise.", validImport)
	importTool.Idempotent = false
	importTool.Schema = object(map[string]any{
		"text":    map[string]any{"type": "string", "minLength": 1, "maxLength": 1 << 20, "description": "Share links, one per line, or a subscription body."},
		"group":   map[string]any{"type": "string", "maxLength": 256, "description": "Group for the imported nodes."},
		"indices": map[string]any{"type": "array", "maxItems": 1000, "items": map[string]any{"type": "integer", "minimum": 0}},
	}, "text")
	importTool.Run = importNodes
	previewImport := dtoTool(readTool, "preview_node_import", "Preview node import", "nodes.import.preview",
		"Parses share links or a subscription body and returns the nodes that import_nodes would add, without saving anything.", func(v *contractnode.ImportRequest) error {
			if strings.TrimSpace(v.Text) == "" || len(v.Text) > 1<<20 {
				return errors.New("text is required (at most 1 MiB)")
			}
			return nil
		})

	return []Tool{
		// Nodes
		idTool(readTool, "get_node", "Get node", "node.get", "Returns one node with its full protocol chain. Secret values are redacted."),
		dtoTool(writeTool, "save_node", "Save node", "nodes.post",
			"Creates a node, or replaces the node with the same id. Leave id empty to create one. The chain lists protocols from the outermost transport to the proxy protocol; read an existing node with get_node for an example. Redacted secrets sent back unchanged keep their stored values.",
			func(v *contractnode.Node) error { newID(&v.ID); return nil }),
		idTool(destructiveTool, "delete_node", "Delete node", "node.delete", "Deletes a node. Nodes referenced by selectors or rules cannot be deleted."),
		previewImport,
		importTool,
		dtoTool(testTool, "test_node_latency", "Test node latency", "node.latency",
			"Measures the latency of a node. type is http (url required) or dns (host and targetDomain); tcp and ipv6 choose the probe transport.",
			func(v *nodeLatencyArguments) error {
				if strings.TrimSpace(v.ID) == "" {
					return errors.New("id is required")
				}
				return nil
			}),

		// Inbounds
		idTool(readTool, "get_inbound", "Get inbound", "inbound.get", "Returns one inbound listener. Secret values are redacted."),
		dtoTool(readTool, "get_inbound_capabilities", "Inbound capabilities", "inbound.capabilities", "Lists the inbound protocols and transports this platform supports.", func(*struct{}) error { return nil }),
		dtoTool(readTool, "get_inbound_status", "Inbound status", "inbounds.status", "Returns the runtime status of every inbound, including listen errors.", func(*struct{}) error { return nil }),
		dtoTool(writeTool, "save_inbound", "Save inbound", "inbound.put",
			"Creates an inbound, or replaces the inbound with the same id. Leave id empty to create one. The listener starts or restarts immediately; check get_inbound_status afterwards.",
			func(v *contractinbound.Inbound) error { newID(&v.ID); return nil }),
		idTool(destructiveTool, "delete_inbound", "Delete inbound", "inbound.delete", "Deletes an inbound and stops its listener."),

		// HTTP Gateway
		dtoTool(readTool, "get_gateway", "Get HTTP Gateway", "gateway.workspace.get", "Returns the whole HTTP Gateway workspace: gateways, rules, filters and settings.", func(*struct{}) error { return nil }),
		dtoTool(readTool, "get_gateway_status", "HTTP Gateway status", "gateway.status", "Returns the runtime status of the HTTP Gateways.", func(*struct{}) error { return nil }),
		dtoTool[contractgateway.Workspace](writeTool, "save_gateway", "Save HTTP Gateway", "gateway.workspace.put",
			"Replaces the whole HTTP Gateway workspace. Read it with get_gateway first, change it, and send it back including its revision.", nil),
		dtoTool[contractgateway.TestRequest](testTool, "test_gateway", "Test HTTP Gateway", "gateway.test",
			"Evaluates a request against an HTTP Gateway and reports the matching rule and action, without forwarding the request.", nil),

		// Route lists
		{Name: "list_route_lists", Title: "List route lists", Operation: "route.lists.get", ReadOnly: true, Idempotent: true,
			Description: "Lists host, IP and process lists used by routing rules.", Schema: object(pagingProperties), Arguments: paged},
		idTool(readTool, "get_route_list", "Get route list", "route.list.get", "Returns one route list with its entries."),
		dtoTool[contractroute.RouteListDetail](writeTool, "create_route_list", "Create route list", "route.lists.post", "Creates a route list. Use it from rules created with create_route_rule.", nil),
		dtoTool(writeTool, "update_route_list", "Update route list", "route.list.put", "Replaces the route list with the given id.", func(v *routeListUpdate) error {
			return requireID(&idArguments{ID: v.ID})
		}),
		idTool(destructiveTool, "delete_route_list", "Delete route list", "route.list.delete", "Deletes a route list. Lists used by rules cannot be deleted."),

		// Rules
		idTool(readTool, "get_route_rule", "Get route rule", "route.rule.get", "Returns one routing rule with its condition expression and action."),
		dtoTool[contractroute.RuleDraft](writeTool, "create_route_rule", "Create route rule", "route.rules.post", "Creates a routing rule. Read a rule with get_route_rule for an example of the condition expression. Changes take effect after routing is applied.", nil),
		dtoTool(writeTool, "update_route_rule", "Update route rule", "route.rule.put", "Replaces the routing rule with the given id.", func(v *routeRuleUpdate) error {
			return requireID(&idArguments{ID: v.ID})
		}),
		idTool(destructiveTool, "delete_route_rule", "Delete route rule", "route.rule.delete", "Deletes a routing rule."),
		dtoTool(readTool, "test_route", "Test routing", "route.rules.test", "Shows which rule, action and resolver apply to a host or IP address with the active routing configuration.", func(v *contractroute.RuleTestRequest) error {
			if strings.TrimSpace(v.Host) == "" {
				return errors.New("host is required")
			}
			return nil
		}),
		dtoTool(writeTool, "apply_routes", "Apply routing", "route.apply", "Activates saved routing rule and list changes now.", func(*struct{}) error { return nil }),
		dtoTool(readTool, "get_route_activation", "Routing activation status", "route.activation", "Reports whether saved routing changes are active, pending or failed.", func(*struct{}) error { return nil }),

		// DNS
		idTool(readTool, "get_resolver", "Get resolver", "resolver.get", "Returns one DNS resolver. Secret values are redacted."),
		dtoTool(writeTool, "save_resolver", "Save resolver", "resolvers.post", "Creates a DNS resolver, or replaces the resolver with the same id. Leave id empty to create one.", func(v *contractresolver.Resolver) error {
			newID(&v.ID)
			return nil
		}),
		idTool(destructiveTool, "delete_resolver", "Delete resolver", "resolver.delete", "Deletes a DNS resolver. Resolvers used by rules cannot be deleted."),
		dtoTool(testTool, "test_resolver", "Test resolver", "resolver.test", "Resolves a domain with the given resolver configuration, which need not be saved, and returns the answers.", func(v *contractresolver.TestRequest) error {
			if strings.TrimSpace(v.Domain) == "" {
				return errors.New("domain is required")
			}
			return nil
		}),

		// Hosts
		{Name: "list_hosts", Title: "List hosts", Operation: "resolver.hosts.entries", ReadOnly: true, Idempotent: true,
			Description: "Lists static host mappings.", Schema: object(pagingProperties), Arguments: paged},
		dtoTool[contractresolver.HostEntry](writeTool, "add_host", "Add host", "resolver.hosts.entry.post", "Maps a host name to an IP address or another host name. Fails when the host already exists.", nil),
		dtoTool[contractresolver.HostEntry](writeTool, "update_host", "Update host", "resolver.hosts.entry.put", "Changes the target of an existing host mapping.", nil),
		func() Tool {
			t := dtoTool(destructiveTool, "delete_host", "Delete host", "resolver.hosts.entry.delete", "Deletes a static host mapping.", func(v *hostArguments) error {
				if strings.TrimSpace(v.Host) == "" {
					return errors.New("host is required")
				}
				return nil
			})
			t.Schema = object(map[string]any{"host": map[string]any{"type": "string", "minLength": 1, "maxLength": 253}}, "host")
			return t
		}(),
	}
}
