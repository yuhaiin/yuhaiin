// Package mcpserver is the Model Context Protocol resource server. It owns only
// the MCP protocol surface (Streamable HTTP via the official Go SDK, the tool
// registry, argument validation and result conversion). Authentication,
// authorization and token handling belong to the management identity runtime
// and its OAuth Authorization Server; tool execution belongs to the HTTP API
// operations, which this package calls in process.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/management/oauth"
	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Path is the MCP Streamable HTTP endpoint.
const Path = "/mcp"

// Server serves MCP over Streamable HTTP.
type Server struct {
	operations *httpapi.Operations
	tools      []Tool
	version    string
	handler    http.Handler
}

// New returns an MCP server whose tools run ops. Tools whose operation is not
// available in ops are omitted.
func New(ops *httpapi.Operations, version string) (*Server, error) {
	s := &Server{operations: ops, version: version}
	for _, tool := range builtinTools() {
		required, ok := ops.Permission(tool.Operation)
		if !ok {
			continue
		}
		tool.permission = required
		s.tools = append(s.tools, tool)
	}
	if len(s.tools) == 0 {
		return nil, errors.New("no MCP tools are available")
	}
	s.handler = mcp.NewStreamableHTTPHandler(s.server, &mcp.StreamableHTTPOptions{
		// Each POST carries the bearer token and is authorized on its own, so
		// no session can outlive a revoked token or a changed permission.
		Stateless:    true,
		JSONResponse: true,
		// The SDK check rejects loopback connections whose Host is not
		// loopback, which would break every reverse proxy and tunnel in front
		// of Yuhaiin. DNS rebinding is not a risk here: the management gate
		// validates Origin and every request needs an OAuth bearer token.
		DisableLocalhostProtection:   true,
		MaxRequestBodyBytes:          1 << 20,
		PropagateRequestCancellation: true,
	})
	return s, nil
}

// Resource describes MCP as an OAuth protected resource. Its scopes are
// mcp:connect, secrets:manage and the permissions of its tools, all taken from
// the shared permission registry.
func (s *Server) Resource() oauth.Resource {
	// secrets:manage is offered because configuration tools can only save
	// objects that contain credentials (node passwords, inbound users) with it.
	scopes := []permission.Permission{permission.MCPConnect, permission.SecretsManage}
	for _, tool := range s.tools {
		for _, required := range append([]permission.Permission{tool.permission}, tool.Requires...) {
			if !slices.Contains(scopes, required) {
				scopes = append(scopes, required)
			}
		}
	}
	return oauth.Resource{ID: "mcp", Name: "Yuhaiin MCP server", Path: Path, Prefixes: []string{Path}, Scopes: scopes, Required: permission.MCPConnect}
}

// Tools returns the registered tools and their required permissions.
func (s *Server) Tools() map[string]permission.Permission {
	out := make(map[string]permission.Permission, len(s.tools))
	for _, tool := range s.tools {
		out[tool.Name] = tool.permission
	}
	return out
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// server builds the MCP server for one HTTP request. Only tools the request
// principal may run are listed; each call is authorized again when it runs.
func (s *Server) server(r *http.Request) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "yuhaiin", Title: "Yuhaiin", Version: s.version}, &mcp.ServerOptions{
		Instructions: "Tools for inspecting and operating a Yuhaiin proxy. Every call is limited to the permissions granted to this connection.",
	})
	for _, tool := range s.tools {
		if !tool.allowed(r.Context()) {
			continue
		}
		server.AddTool(tool.definition(), s.call(tool))
	}
	return server
}

func (s *Server) call(tool Tool) mcp.ToolHandler {
	return func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Annotations are hints for clients, never authorization. The
		// permission is checked against the current request principal.
		if !tool.allowed(ctx) {
			return errorResult(fmt.Sprintf("permission denied: %s requires %s", tool.Name, tool.permissions())), nil
		}
		arguments := []byte(request.Params.Arguments)
		if len(bytes.TrimSpace(arguments)) == 0 || string(bytes.TrimSpace(arguments)) == "null" {
			arguments = []byte("{}")
		}
		body, err := tool.Arguments(arguments)
		if err != nil {
			return errorResult("invalid arguments: " + err.Error()), nil
		}
		// MCP output is never allowed to reveal secrets, whatever headers the
		// client sends.
		if capabilities, managed := secret.FromContext(ctx); managed {
			capabilities.Reveal = false
			ctx = secret.WithCapabilities(ctx, capabilities)
		} else {
			ctx = secret.WithCapabilities(ctx, secret.Capabilities{})
		}
		var result any
		if tool.Run != nil {
			result, err = tool.Run(ctx, s.operations.Invoke, body)
		} else {
			result, err = s.operations.Invoke(ctx, tool.Operation, body)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			status, code, message := httpapi.ErrorStatus(err)
			if status == http.StatusInternalServerError {
				message = "the operation failed"
			}
			return errorResult(fmt.Sprintf("%s: %s", code, message)), nil
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return errorResult("the result could not be encoded"), nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}}}, nil
	}
}

func (t Tool) permissions() string {
	names := []string{string(t.permission)}
	for _, p := range t.Requires {
		names = append(names, string(p))
	}
	return strings.Join(names, " and ")
}

func (t Tool) allowed(ctx context.Context) bool {
	if !permission.Allowed(ctx, t.permission) {
		return false
	}
	for _, p := range t.Requires {
		if !permission.Allowed(ctx, p) {
			return false
		}
	}
	return true
}

func errorResult(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}
