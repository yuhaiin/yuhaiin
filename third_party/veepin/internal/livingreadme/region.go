// Package livingreadme rewrites the machine-managed regions of the project's
// README — the interop matrix, the microbenchmark table, and the interop
// throughput table — from results a CI job produces. The prose around each
// region is hand-written; only the content between a pair of marker comments is
// generated, so CI can refresh the numbers on every push to main without
// touching anything a human wrote.
//
// A region is delimited by a pair of HTML comments, which render invisibly in
// Markdown:
//
//	<!-- livingreadme:interop:start -->
//	...generated content...
//	<!-- livingreadme:interop:end -->
//
// ReplaceRegion swaps the content between them. It is deliberately dumb about
// the content — the renderers in this package produce it — so the same
// mechanism serves every region and is trivial to unit-test.
package livingreadme

import (
	"fmt"
	"strings"
)

// Marker names for the three managed regions.
const (
	RegionInterop      = "interop"
	RegionBenchmark    = "benchmark"
	RegionInteropBench = "interop-benchmark"
)

// startMarker and endMarker return the exact comment lines that fence a region.
func startMarker(region string) string { return "<!-- livingreadme:" + region + ":start -->" }
func endMarker(region string) string   { return "<!-- livingreadme:" + region + ":end -->" }

// ReplaceRegion returns doc with the content between region's start and end
// markers replaced by body. The markers themselves are preserved, and body is
// framed by blank lines so the result stays valid Markdown regardless of whether
// body already ends in a newline. It is idempotent: replacing a region with the
// same body yields identical bytes.
//
// It errors rather than guessing if the markers are missing, out of order, or
// duplicated — a malformed README should fail the CI step loudly, not be
// silently half-rewritten.
func ReplaceRegion(doc []byte, region, body string) ([]byte, error) {
	start, end := startMarker(region), endMarker(region)
	s := string(doc)

	si := strings.Index(s, start)
	if si < 0 {
		return nil, fmt.Errorf("livingreadme: start marker for %q not found", region)
	}
	if strings.Contains(s[si+len(start):], start) {
		return nil, fmt.Errorf("livingreadme: duplicate start marker for %q", region)
	}
	ei := strings.Index(s, end)
	if ei < 0 {
		return nil, fmt.Errorf("livingreadme: end marker for %q not found", region)
	}
	if strings.Contains(s[ei+len(end):], end) {
		return nil, fmt.Errorf("livingreadme: duplicate end marker for %q", region)
	}
	if ei < si+len(start) {
		return nil, fmt.Errorf("livingreadme: end marker precedes start marker for %q", region)
	}

	var b strings.Builder
	b.WriteString(s[:si+len(start)])
	b.WriteString("\n")
	b.WriteString(strings.TrimRight(strings.TrimLeft(body, "\n"), "\n"))
	b.WriteString("\n")
	b.WriteString(s[ei:])
	return []byte(b.String()), nil
}

// HasRegion reports whether doc contains both markers for region, in order.
func HasRegion(doc []byte, region string) bool {
	s := string(doc)
	si := strings.Index(s, startMarker(region))
	ei := strings.Index(s, endMarker(region))
	return si >= 0 && ei > si
}
