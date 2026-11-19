package route

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/route/processpath"
)

// processMatcher is an immutable process list index. It matches the path
// recorded on the connection; the recorded path itself is never rewritten.
type processMatcher struct {
	index *processpath.Index
}

// An empty index never matches, so its flavor does not matter.
var emptyProcessIndex = &processMatcher{index: processpath.NewBuilder(processpath.Unix).Build()}

func emptyProcessMatcher() *processMatcher { return emptyProcessIndex }

func (h *processMatcher) Search(ctx context.Context, _ netapi.Address) []string {
	return h.index.Match(netapi.GetContext(ctx).GetProcessName())
}

// Empty reports whether no entry can match on this platform, so that the
// rules_only lookup mode can skip process lookups.
func (h *processMatcher) Empty() bool { return h.index.Empty() }

func (h *processMatcher) Include(list string) bool {
	return slices.Contains(h.index.Lists(), list)
}

// processMatcherBuilder compiles process lists for the host platform.
type processMatcherBuilder struct {
	builder *processpath.Builder
}

// processPathFlavor is the path syntax process lists are compiled for. Tests
// pin it so that their paths mean the same on every host.
var processPathFlavor = processpath.Host

func newProcessMatcherBuilder() *processMatcherBuilder {
	return &processMatcherBuilder{builder: processpath.NewBuilder(processPathFlavor())}
}

func (b *processMatcherBuilder) register(list string) { b.builder.Register(list) }

// maxReportedEntries bounds the invalid entries named in one issue.
const maxReportedEntries = 3

// addList compiles every entry of a process list. Invalid entries are left
// out and described by the returned issue; the list then cannot prove that a
// process is absent, so callers treat it as incomplete. Line numbers are
// reported for local lists.
func (b *processMatcherBuilder) addList(list contractroute.RouteListDetail, values iter.Seq[string]) *contractroute.ListActivationIssue {
	b.register(list.ID)
	var problems []string
	invalid := 0
	add := func(line int, value string) {
		if _, err := b.builder.Add(value, list.ID); err != nil {
			invalid++
			if len(problems) < maxReportedEntries {
				if line > 0 {
					problems = append(problems, fmt.Sprintf("line %d: %v", line, err))
				} else {
					problems = append(problems, err.Error())
				}
			}
		}
	}
	if list.Source.Type != "remote" && list.Source.Local != nil {
		for i, raw := range list.Source.Local.Lists {
			if value := trimRule(raw); value != "" {
				add(i+1, value)
			}
		}
	} else if values != nil {
		for value := range values {
			add(0, value)
		}
	}
	if invalid == 0 {
		return nil
	}
	message := strings.Join(problems, "; ")
	if invalid > len(problems) {
		message += fmt.Sprintf(" (and %d more)", invalid-len(problems))
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return &contractroute.ListActivationIssue{ID: list.ID, Name: list.Name, Error: message}
}

func (b *processMatcherBuilder) build() *processMatcher {
	return &processMatcher{index: b.builder.Build()}
}
