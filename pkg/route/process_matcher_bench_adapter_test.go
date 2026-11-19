package route

import "github.com/Asutorufa/yuhaiin/pkg/route/processpath"

// benchProcessMatcher builds the index the way configuration activation
// does, for an explicit flavor so Windows cases run on any host.
func benchProcessMatcher(windows bool, entries []benchProcessEntry) *processMatcher {
	flavor := processpath.Linux
	if windows {
		flavor = processpath.Windows
	}
	builder := processpath.NewBuilder(flavor)
	for _, entry := range entries {
		if _, err := builder.Add(entry.value, entry.list); err != nil {
			panic(err)
		}
	}
	return &processMatcher{index: builder.Build()}
}

func benchProcessLists(matcher *processMatcher) *Lists {
	lists := &Lists{}
	lists.processTrie.Store(matcher)
	return lists
}
