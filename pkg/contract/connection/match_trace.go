package connection

// MatchTraceTemplate is compiled once per routing-snapshot rule and shared by
// every connection that evaluates the rule. None of its children are mutated.
// A connection retains just this pointer alongside its existing flat results.
type MatchTraceTemplate struct {
	Type         string
	Label        string
	Constant     string // "true", "false", or "" when a leaf emits a history result
	EmitsHistory bool
	Children     []MatchTraceTemplate
}

type traceValue uint8

const (
	traceFalse traceValue = iota
	traceTrue
	traceUnknown
)

func traceValueState(value traceValue) string {
	switch value {
	case traceTrue:
		return "hit"
	case traceFalse:
		return "miss"
	default:
		return "unknown"
	}
}

// ReconstructMatchTrace replays the ordered, already-recorded leaf results
// against the immutable template. It never evaluates the matcher again or
// touches the network. Work and allocations happen only on an explicit
// trace-detail request, not on connection creation or periodic listing.
//
// When old/partial history cannot be mapped precisely, the node is unknown,
// never an invented false or true.
func ReconstructMatchTrace(template *MatchTraceTemplate, history []MatchResult) *MatchTrace {
	if template == nil {
		return nil
	}
	index := 0
	var walk func(node *MatchTraceTemplate, evaluate bool) (traceValue, MatchTrace)
	walk = func(node *MatchTraceTemplate, evaluate bool) (traceValue, MatchTrace) {
		trace := MatchTrace{Type: node.Type, Label: node.Label}
		if !evaluate {
			trace.State = "skipped"
			for i := range node.Children {
				_, child := walk(&node.Children[i], false)
				trace.Children = append(trace.Children, child)
			}
			return traceUnknown, trace
		}

		var result traceValue
		switch node.Type {
		case "and":
			result = traceTrue
			unknown := false
			for i := range node.Children {
				shouldEvaluate := result != traceFalse
				value, child := walk(&node.Children[i], shouldEvaluate)
				trace.Children = append(trace.Children, child)
				if !shouldEvaluate {
					continue
				}
				switch value {
				case traceFalse:
					result = traceFalse
				case traceUnknown:
					unknown = true
				}
			}
			if result != traceFalse && unknown {
				result = traceUnknown
			}
		case "or":
			result = traceFalse
			unknown := false
			for i := range node.Children {
				shouldEvaluate := result != traceTrue
				value, child := walk(&node.Children[i], shouldEvaluate)
				trace.Children = append(trace.Children, child)
				if !shouldEvaluate {
					continue
				}
				switch value {
				case traceTrue:
					result = traceTrue
				case traceUnknown:
					unknown = true
				}
			}
			if result != traceTrue && unknown {
				result = traceUnknown
			}
		case "not":
			result = traceUnknown
			if len(node.Children) == 1 {
				value, child := walk(&node.Children[0], true)
				trace.Children = []MatchTrace{child}
				switch value {
				case traceTrue:
					result = traceFalse
				case traceFalse:
					result = traceTrue
				}
			}
		default:
			switch node.Constant {
			case "true":
				result = traceTrue
			case "false":
				result = traceFalse
			default:
				result = traceUnknown
				if node.EmitsHistory && index < len(history) {
					item := history[index]
					index++
					trace.Kind, trace.ID = item.Kind, item.ID
					if item.ListName != "" {
						trace.Label = item.ListName
					}
					if item.Kind == "list-unavailable" || (item.Kind == "list-incomplete" && !item.Matched) {
						result = traceUnknown
					} else if item.Matched {
						result = traceTrue
					} else {
						result = traceFalse
					}
				}
			}
		}
		trace.State = traceValueState(result)
		return result, trace
	}
	_, out := walk(template, true)
	return &out
}
