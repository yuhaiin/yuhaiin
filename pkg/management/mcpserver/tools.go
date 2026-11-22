package mcpserver

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool maps one MCP tool onto one HTTP API operation. The schema is explicit
// and closed; Arguments validates the MCP arguments and converts them into the
// operation's existing request DTO, so no business logic lives here.
type Tool struct {
	Name        string
	Title       string
	Description string
	Operation   string
	Schema      map[string]any
	ReadOnly    bool
	Destructive bool
	Idempotent  bool
	OpenWorld   bool
	Arguments   func([]byte) ([]byte, error)
	// Run, when set, replaces the single Operation call for a tool that
	// composes several operations. Every call it makes through invoke is
	// authorized on its own.
	Run func(ctx context.Context, invoke Invoker, body []byte) (any, error)
	// Requires lists permissions needed beyond the operation's own, such as
	// secrets:read for raw logs. The operation enforces them too.
	Requires []permission.Permission

	permission permission.Permission
}

// Invoker runs one HTTP API operation with the request principal.
type Invoker func(ctx context.Context, operation string, body []byte) (any, error)

func (t Tool) definition() *mcp.Tool {
	annotations := &mcp.ToolAnnotations{Title: t.Title, ReadOnlyHint: t.ReadOnly, IdempotentHint: t.Idempotent}
	required := t.permissions()
	destructive, openWorld := t.Destructive, t.OpenWorld
	annotations.DestructiveHint, annotations.OpenWorldHint = &destructive, &openWorld
	return &mcp.Tool{Name: t.Name, Title: t.Title, Description: t.Description + " Requires " + required + ".", InputSchema: t.Schema, Annotations: annotations}
}

func object(properties map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

var pagingProperties = map[string]any{
	"query":     map[string]any{"type": "string", "maxLength": 256, "description": "Case-insensitive text filter."},
	"page":      map[string]any{"type": "integer", "minimum": 1, "default": 1},
	"page_size": map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
}

// decodeStrict rejects unknown members, as the closed schemas declare.
func decodeStrict(raw []byte, out any) error {
	if err := json.Unmarshal(raw, out, json.RejectUnknownMembers(true)); err != nil {
		return errors.New("arguments do not match the tool schema")
	}
	return nil
}

func noArguments(raw []byte) ([]byte, error) {
	var empty struct{}
	if err := decodeStrict(raw, &empty); err != nil {
		return nil, err
	}
	return []byte("{}"), nil
}

type pageArguments struct {
	Query    string `json:"query"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

func (p *pageArguments) normalize() error {
	if len(p.Query) > 256 || p.Page < 0 || p.PageSize < 0 || p.PageSize > 200 {
		return errors.New("query must be at most 256 characters, page positive and page_size at most 200")
	}
	if p.Page == 0 {
		p.Page = 1
	}
	if p.PageSize == 0 {
		p.PageSize = 50
	}
	return nil
}

func paged(raw []byte) ([]byte, error) {
	var args pageArguments
	if err := decodeStrict(raw, &args); err != nil {
		return nil, err
	}
	if err := args.normalize(); err != nil {
		return nil, err
	}
	return json.Marshal(args)
}

func validIDs(ids []string, limit int, numeric bool) error {
	if len(ids) == 0 || len(ids) > limit {
		return fmt.Errorf("between 1 and %d identifiers are required", limit)
	}
	for _, id := range ids {
		if id == "" || len(id) > 256 || strings.ContainsFunc(id, func(r rune) bool { return r < 0x20 }) {
			return errors.New("identifiers must be short, non-empty strings")
		}
		if numeric {
			if _, err := strconv.ParseUint(id, 10, 64); err != nil {
				return errors.New("connection identifiers are decimal numbers")
			}
		}
	}
	return nil
}

func builtinTools() []Tool {
	return slices.Concat(statusTools(), configurationTools(), diagnosticTools())
}

func statusTools() []Tool {
	return []Tool{
		{Name: "get_system_info", Title: "System information", Operation: "info", ReadOnly: true, Idempotent: true,
			Description: "Returns the Yuhaiin version, build and platform.", Schema: object(map[string]any{}), Arguments: noArguments},
		{Name: "get_settings", Title: "General settings", Operation: "settings.get", ReadOnly: true, Idempotent: true,
			Description: "Returns the general settings. Secret values are always redacted.", Schema: object(map[string]any{}), Arguments: noArguments},
		{Name: "list_nodes", Title: "List nodes", Operation: "nodes.get", ReadOnly: true, Idempotent: true,
			Description: "Lists outbound nodes, optionally filtered by text, group or enabled state. Secret values are redacted.",
			Schema: object(map[string]any{
				"query": pagingProperties["query"], "page": pagingProperties["page"], "page_size": pagingProperties["page_size"],
				"group":        map[string]any{"type": "string", "maxLength": 256},
				"enabled_only": map[string]any{"type": "boolean"},
			}),
			Arguments: func(raw []byte) ([]byte, error) {
				var args struct {
					pageArguments
					Group       string `json:"group"`
					EnabledOnly bool   `json:"enabled_only"`
				}
				if err := decodeStrict(raw, &args); err != nil {
					return nil, err
				}
				if err := args.normalize(); err != nil || len(args.Group) > 256 {
					return nil, errors.New("invalid paging or group argument")
				}
				return json.Marshal(args)
			}},
		{Name: "get_selected_node", Title: "Selected node", Operation: "nodes.selected", ReadOnly: true, Idempotent: true,
			Description: "Returns the nodes currently selected for TCP and UDP traffic.", Schema: object(map[string]any{}), Arguments: noArguments},
		{Name: "list_inbounds", Title: "List inbounds", Operation: "inbounds.get", ReadOnly: true, Idempotent: true,
			Description: "Lists inbound listeners. Secret values are redacted.", Schema: object(pagingProperties), Arguments: paged},
		{Name: "get_connections", Title: "Active connections", Operation: "connections", ReadOnly: true, Idempotent: true,
			Description: "Lists the active proxied connections.", Schema: object(map[string]any{}), Arguments: noArguments},
		{Name: "get_traffic", Title: "Traffic totals", Operation: "connections.total", ReadOnly: true, Idempotent: true,
			Description: "Returns total upload and download counters.", Schema: object(map[string]any{}), Arguments: noArguments},
		{Name: "get_routes", Title: "Route rules", Operation: "route.rules.get", ReadOnly: true, Idempotent: true,
			Description: "Lists routing rules in priority order.", Schema: object(pagingProperties), Arguments: paged},
		{Name: "get_resolvers", Title: "DNS resolvers", Operation: "resolvers.get", ReadOnly: true, Idempotent: true,
			Description: "Lists configured DNS resolvers. Secret values are redacted.", Schema: object(pagingProperties), Arguments: paged},
		{Name: "get_system_network", Title: "System network status", Operation: "systemNetwork.status", ReadOnly: true, Idempotent: true,
			Description: "Returns the status of operating system routing and forwarding managed by Yuhaiin.", Schema: object(map[string]any{}), Arguments: noArguments},
		{Name: "select_node", Title: "Select node", Operation: "nodes.select", Idempotent: true,
			Description: "Makes a node the default destination for TCP and, unless udp_node_id is given, UDP traffic. This changes how all traffic is routed.",
			Schema: object(map[string]any{
				"node_id":     map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "description": "Node ID from list_nodes, used for TCP."},
				"udp_node_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "description": "Node ID for UDP; defaults to node_id."},
			}, "node_id"),
			Arguments: func(raw []byte) ([]byte, error) {
				var args struct {
					NodeID    string `json:"node_id"`
					UDPNodeID string `json:"udp_node_id"`
				}
				if err := decodeStrict(raw, &args); err != nil {
					return nil, err
				}
				if args.UDPNodeID == "" {
					args.UDPNodeID = args.NodeID
				}
				if err := validIDs([]string{args.NodeID, args.UDPNodeID}, 2, false); err != nil {
					return nil, err
				}
				return json.Marshal(map[string]string{"tcpId": args.NodeID, "udpId": args.UDPNodeID})
			}},
		{Name: "close_connections", Title: "Close connections", Operation: "connections.close", Destructive: true, Idempotent: true,
			Description: "Closes active connections by ID. Applications using them are disconnected.",
			Schema: object(map[string]any{
				"ids": map[string]any{"type": "array", "minItems": 1, "maxItems": 1000, "items": map[string]any{"type": "string", "pattern": "^[0-9]+$"}},
			}, "ids"),
			Arguments: func(raw []byte) ([]byte, error) {
				var args struct {
					IDs []string `json:"ids"`
				}
				if err := decodeStrict(raw, &args); err != nil {
					return nil, err
				}
				if err := validIDs(args.IDs, 1000, true); err != nil {
					return nil, err
				}
				return json.Marshal(map[string][]string{"ids": args.IDs})
			}},
		{Name: "update_subscription", Title: "Update subscriptions", Operation: "subscriptions.update", OpenWorld: true,
			Description: "Downloads the named subscriptions now and replaces their nodes. This contacts the subscription servers.",
			Schema: object(map[string]any{
				"names": map[string]any{"type": "array", "minItems": 1, "maxItems": 64, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}},
			}, "names"),
			Arguments: func(raw []byte) ([]byte, error) {
				var args struct {
					Names []string `json:"names"`
				}
				if err := decodeStrict(raw, &args); err != nil {
					return nil, err
				}
				if err := validIDs(args.Names, 64, false); err != nil {
					return nil, err
				}
				return json.Marshal(map[string][]string{"names": args.Names})
			}},
	}
}
