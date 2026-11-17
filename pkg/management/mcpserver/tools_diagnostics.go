package mcpserver

import (
	"context"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

// Diagnostic tools read logs, runtime statistics, profiles and traffic
// history so an MCP client can analyze performance and failures. Like every
// tool they run existing HTTP API operations.

var profileTypes = func() []any {
	out := make([]any, len(contracttools.ProfileTypes))
	for i, kind := range contracttools.ProfileTypes {
		out[i] = kind
	}
	return out
}()

var analysisProperties = map[string]any{
	"mode":        map[string]any{"type": "string", "enum": []any{"functions", "stacks"}, "description": "functions: top functions by flat and cumulative value (pprof top). stacks: top complete call stacks (pprof traces)."},
	"sample_type": map[string]any{"type": "string", "maxLength": 64, "description": "Value to rank by, such as cpu, inuse_space, alloc_space, contentions or delay. Defaults to the profile's main value."},
	"limit":       map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "default": 25},
	"focus":       map[string]any{"type": "string", "maxLength": 256, "description": "Only count samples whose stack contains a function name with this text, for example yuhaiin/pkg/net."},
}

type analysisArguments struct {
	Mode       string `json:"mode"`
	SampleType string `json:"sample_type"`
	Limit      int    `json:"limit"`
	Focus      string `json:"focus"`
}

func (a analysisArguments) request(id string) contracttools.ProfileAnalysisRequest {
	return contracttools.ProfileAnalysisRequest{ID: id, Mode: a.Mode, SampleType: a.SampleType, Limit: a.Limit, Focus: a.Focus, Wait: true}
}

type captureArguments struct {
	Type    string `json:"type"`
	Seconds int    `json:"seconds"`
	Keep    bool   `json:"keep"`
	analysisArguments
}

func validProfileType(kind string) bool {
	return slices.Contains(contracttools.ProfileTypes, kind)
}

func (c *captureArguments) validate() error {
	if !validProfileType(c.Type) {
		return errors.New("type must be one of " + strings.Join(contracttools.ProfileTypes, ", "))
	}
	if c.Type == "cpu" && c.Seconds == 0 {
		c.Seconds = 10
	}
	if c.Seconds < 0 || c.Seconds > 120 {
		return errors.New("seconds must be between 0 and 120")
	}
	return nil
}

// captureProfile starts a profile, waits for it and summarizes it in one call.
func captureProfile(ctx context.Context, invoke Invoker, body []byte) (any, error) {
	var args captureArguments
	if err := json.Unmarshal(body, &args); err != nil {
		return nil, err
	}
	started, err := invoke(ctx, "profiler.start", mustMarshal(contracttools.ProfileRequest{Type: args.Type, Seconds: args.Seconds}))
	if err != nil {
		return nil, err
	}
	var session contracttools.ProfileSession
	if err := json.Unmarshal(mustMarshal(started), &session); err != nil || session.ID == "" {
		return nil, errors.New("unexpected profiler response")
	}
	analysis, err := invoke(ctx, "profiler.analyze", mustMarshal(args.request(session.ID)))
	if !args.Keep {
		// The summary is the result; the raw profile is not kept around.
		_, _ = invoke(context.WithoutCancel(ctx), "profiler.delete", mustMarshal(idArguments{ID: session.ID}))
	}
	return analysis, err
}

func mustMarshal(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

// window converts a look-back period into the RFC3339 range the traffic
// operations take.
type windowArguments struct {
	Minutes  int    `json:"minutes"`
	Interval string `json:"interval"`
	Limit    int    `json:"limit"`
}

func windowRange(minutes int) (string, string, error) {
	if minutes == 0 {
		minutes = 60
	}
	if minutes < 1 || minutes > 366*24*60 {
		return "", "", errors.New("minutes must be between 1 and 527040")
	}
	now := time.Now().UTC()
	return now.Add(-time.Duration(minutes) * time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339), nil
}

// limitItems keeps the first limit entries of a list response's items. It
// only shapes the output for a language model; the operation is unchanged.
func limitItems(operation string) func(context.Context, Invoker, []byte) (any, error) {
	return func(ctx context.Context, invoke Invoker, body []byte) (any, error) {
		var args struct {
			Limit int `json:"limit"`
		}
		if err := json.Unmarshal(body, &args); err != nil {
			return nil, err
		}
		if args.Limit == 0 {
			args.Limit = 50
		}
		result, err := invoke(ctx, operation, []byte("{}"))
		if err != nil {
			return nil, err
		}
		var generic map[string]any
		if err := json.Unmarshal(mustMarshal(result), &generic); err != nil {
			return nil, err
		}
		items, _ := generic["items"].([]any)
		generic["total"] = len(items)
		if len(items) > args.Limit {
			generic["items"] = items[:args.Limit]
			generic["truncated"] = true
		}
		return generic, nil
	}
}

func limitSchema(description string) map[string]any {
	return object(map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 50, "description": description}})
}

func validLimit(raw []byte) ([]byte, error) {
	var args struct {
		Limit int `json:"limit"`
	}
	if err := decodeStrict(raw, &args); err != nil {
		return nil, err
	}
	if args.Limit < 0 || args.Limit > 1000 {
		return nil, errors.New("limit must be between 1 and 1000")
	}
	return raw, nil
}

func diagnosticTools() []Tool {
	logs := Tool{Name: "get_logs", Title: "Recent logs", Operation: "logs.recent", ReadOnly: true, Idempotent: true,
		Description: "Returns the newest lines of the Yuhaiin log, oldest first, optionally filtered by minimum level and text. Logs can contain credentials, so this needs secrets:read and every read is recorded in the security audit.",
		Requires:    []permission.Permission{permission.SecretsRead},
		Schema: object(map[string]any{
			"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
			"level":    map[string]any{"type": "string", "enum": []any{"debug", "info", "warn", "error"}, "description": "Minimum level."},
			"contains": map[string]any{"type": "string", "maxLength": 256, "description": "Case-insensitive text filter."},
		}),
		Arguments: strictDTO[contracttools.LogQuery](nil)}

	capture := Tool{Name: "capture_profile", Title: "Capture and analyze a profile", Operation: "profiler.start", ReadOnly: true,
		Description: "Collects a runtime profile and returns its summary in one call: cpu samples for seconds (default 10); heap, allocs, goroutine, mutex and block are snapshots, or deltas over seconds when set. Use it to find CPU hot spots, memory growth, goroutine leaks or lock contention. Runtime profiling must be enabled in the general settings.",
		Schema: func() map[string]any {
			properties := map[string]any{
				"type":    map[string]any{"type": "string", "enum": profileTypes},
				"seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": 120},
				"keep":    map[string]any{"type": "boolean", "description": "Keep the profile for analyze_profile and the Web UI viewer (30 minutes)."},
			}
			maps.Copy(properties, analysisProperties)
			return object(properties, "type")
		}(),
		Arguments: func(raw []byte) ([]byte, error) {
			var args captureArguments
			if err := decodeStrict(raw, &args); err != nil {
				return nil, err
			}
			if err := args.validate(); err != nil {
				return nil, err
			}
			return json.Marshal(args)
		},
		Run: captureProfile}

	analyze := Tool{Name: "analyze_profile", Title: "Analyze a profile", Operation: "profiler.analyze", ReadOnly: true, Idempotent: true,
		Description: "Summarizes a profile from list_profiles or capture_profile with keep, for example with another sample_type, mode or focus. Waits for a running profile to finish.",
		Schema: func() map[string]any {
			properties := map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 64}}
			maps.Copy(properties, analysisProperties)
			return object(properties, "id")
		}(),
		Arguments: func(raw []byte) ([]byte, error) {
			var args struct {
				ID string `json:"id"`
				analysisArguments
			}
			if err := decodeStrict(raw, &args); err != nil {
				return nil, err
			}
			if strings.TrimSpace(args.ID) == "" {
				return nil, errors.New("id is required")
			}
			return json.Marshal(args.request(args.ID))
		}}

	telemetry := Tool{Name: "get_traffic_telemetry", Title: "Traffic telemetry", Operation: "connections.telemetry", ReadOnly: true, Idempotent: true,
		Description: "Summarizes traffic over the last minutes: top destinations, processes, nodes and rules by bytes and connections.",
		Schema: object(map[string]any{
			"minutes": map[string]any{"type": "integer", "minimum": 1, "maximum": 527040, "default": 60},
			"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 8, "description": "Entries per ranking."},
		}),
		Arguments: func(raw []byte) ([]byte, error) {
			var args windowArguments
			if err := decodeStrict(raw, &args); err != nil {
				return nil, err
			}
			from, to, err := windowRange(args.Minutes)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"from": from, "to": to, "limit": args.Limit})
		}}

	history := Tool{Name: "get_traffic_history", Title: "Traffic history", Operation: "connections.traffic", ReadOnly: true, Idempotent: true,
		Description: "Returns upload and download totals per hour, day or month over the last minutes.",
		Schema: object(map[string]any{
			"minutes":  map[string]any{"type": "integer", "minimum": 1, "maximum": 527040, "default": 1440},
			"interval": map[string]any{"type": "string", "enum": []any{"hour", "day", "month"}, "default": "hour"},
		}),
		Arguments: func(raw []byte) ([]byte, error) {
			var args windowArguments
			if err := decodeStrict(raw, &args); err != nil {
				return nil, err
			}
			if args.Minutes == 0 {
				args.Minutes = 1440
			}
			from, to, err := windowRange(args.Minutes)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"from": from, "to": to, "interval": args.Interval})
		}}

	return []Tool{
		logs,
		{Name: "get_runtime_stats", Title: "Runtime statistics", Operation: "runtime.stats", ReadOnly: true, Idempotent: true,
			Description: "Returns process statistics: goroutines, heap and stack memory, garbage collection, CPUs and uptime.", Schema: object(map[string]any{}), Arguments: noArguments},
		capture,
		analyze,
		{Name: "list_profiles", Title: "List profiles", Operation: "profiler.sessions", ReadOnly: true, Idempotent: true,
			Description: "Lists kept and running profiles and whether runtime profiling is enabled.", Schema: object(map[string]any{}), Arguments: noArguments},
		idTool(destructiveTool, "delete_profile", "Delete profile", "profiler.delete", "Deletes a kept profile or cancels a running one."),
		dtoTool(testTool, "run_diagnostics", "Network diagnostics", "tools.diagnostics",
			"Checks DNS resolution, routing and connectivity to a host through Yuhaiin and reports each step with evidence.", func(v *contracttools.DiagnosticRequest) error {
				if strings.TrimSpace(v.Host) == "" || len(v.Host) > 253 {
					return errors.New("host is required")
				}
				return nil
			}),
		telemetry,
		history,
		{Name: "get_failed_connections", Title: "Failed connections", Operation: "connections.failed_history", ReadOnly: true, Idempotent: true,
			Description: "Lists recent connection failures with their errors, hosts and processes.", Schema: limitSchema("Maximum entries."), Arguments: validLimit, Run: limitItems("connections.failed_history")},
		{Name: "get_connection_history", Title: "Connection history", Operation: "connections.history", ReadOnly: true, Idempotent: true,
			Description: "Lists recently closed connections with their routing decisions and traffic.", Schema: limitSchema("Maximum entries."), Arguments: validLimit, Run: limitItems("connections.history")},
		{Name: "get_block_history", Title: "Blocked requests", Operation: "route.rules.block_history", ReadOnly: true, Idempotent: true,
			Description: "Lists requests recently blocked by routing rules.", Schema: limitSchema("Maximum entries."), Arguments: validLimit, Run: limitItems("route.rules.block_history")},
		{Name: "trace_connection", Title: "Trace routing of a connection", Operation: "connections.trace", ReadOnly: true, Idempotent: true,
			Description: "Shows how the routing rule at rule_index matched (or did not match) a connection from get_connections or get_connection_history, including the lists and conditions it evaluated.",
			Schema: object(map[string]any{
				"id":         map[string]any{"type": "string", "pattern": "^[0-9]+$", "description": "Connection ID."},
				"rule_index": map[string]any{"type": "integer", "minimum": 0, "description": "Position of the rule in the connection's match history."},
			}, "id"),
			Arguments: func(raw []byte) ([]byte, error) {
				var args struct {
					ID        string `json:"id"`
					RuleIndex int    `json:"rule_index"`
				}
				if err := decodeStrict(raw, &args); err != nil {
					return nil, err
				}
				if err := validIDs([]string{args.ID}, 1, true); err != nil {
					return nil, err
				}
				return json.Marshal(map[string]any{"id": args.ID, "ruleIndex": args.RuleIndex})
			}},
		{Name: "get_node_statuses", Title: "Node health", Operation: "nodes.status", ReadOnly: true, Idempotent: true,
			Description: "Returns outbound health of nodes: recent latency, failures and connection counts.",
			Schema:      object(map[string]any{"ids": map[string]any{"type": "array", "maxItems": 100, "items": map[string]any{"type": "string", "maxLength": 256}}}),
			Arguments: func(raw []byte) ([]byte, error) {
				var args struct {
					IDs []string `json:"ids"`
				}
				if err := decodeStrict(raw, &args); err != nil {
					return nil, err
				}
				return json.Marshal(args)
			}},
		{Name: "get_gateway_statistics", Title: "HTTP Gateway statistics", Operation: "gateway.statistics", ReadOnly: true, Idempotent: true,
			Description: "Returns HTTP Gateway statistics: requests, status classes, latency histogram, rule hits and top hosts.", Schema: object(map[string]any{}), Arguments: noArguments},
	}
}
