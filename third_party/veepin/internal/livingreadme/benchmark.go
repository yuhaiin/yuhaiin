package livingreadme

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Benchmark is one parsed `go test -bench` result line.
type Benchmark struct {
	Pkg    string // short package path, e.g. "internal/nebula"
	Name   string // benchmark name without the -N GOMAXPROCS suffix
	Iters  int64
	NsOp   float64 // ns/op
	MBs    float64 // MB/s, 0 if the benchmark did not call SetBytes
	BOp    int64   // bytes/op, -1 if not reported
	Allocs int64   // allocs/op, -1 if not reported
}

// ParseBenchmarks reads the combined output of `go test -bench=. -benchmem ./...`
// and returns every benchmark result, tagged with the package it came from. It
// tolerates the surrounding goos/goarch/cpu/PASS/ok lines and sub-benchmark
// names.
func ParseBenchmarks(out string) []Benchmark {
	const modulePrefix = "github.com/xen0bit/veepin/"
	var benches []Benchmark
	pkg := ""
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "pkg:"); ok {
			pkg = strings.TrimPrefix(strings.TrimSpace(rest), modulePrefix)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "Benchmark") {
			continue
		}
		// The second field is the iteration count; a line where it is not a
		// number is not a benchmark result (e.g. a log line starting Benchmark).
		iters, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		b := Benchmark{
			Pkg:    pkg,
			Name:   stripProcs(fields[0]),
			Iters:  iters,
			BOp:    -1,
			Allocs: -1,
		}
		// The remaining fields are "<value> <unit>" pairs in any order.
		for i := 2; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				continue
			}
			switch fields[i+1] {
			case "ns/op":
				b.NsOp = v
			case "MB/s":
				b.MBs = v
			case "B/op":
				b.BOp = int64(v)
			case "allocs/op":
				b.Allocs = int64(v)
			}
		}
		benches = append(benches, b)
	}
	return benches
}

// stripProcs removes the trailing "-<N>" GOMAXPROCS suffix Go appends to a
// benchmark name in its output.
func stripProcs(name string) string {
	if i := strings.LastIndex(name, "-"); i > 0 {
		if _, err := strconv.Atoi(name[i+1:]); err == nil {
			return name[:i]
		}
	}
	return name
}

// RenderBenchmarks renders the benchmark results as a Markdown table grouped by
// package, most-alphabetical first, with a provenance footer. The columns adapt:
// throughput is shown when any row measured it.
func RenderBenchmarks(benches []Benchmark, meta Meta) string {
	if len(benches) == 0 {
		return meta.footer()
	}
	sorted := append([]Benchmark(nil), benches...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Pkg != sorted[j].Pkg {
			return sorted[i].Pkg < sorted[j].Pkg
		}
		return sorted[i].Name < sorted[j].Name
	})

	var b strings.Builder
	b.WriteString("| Package | Benchmark | ns/op | Throughput | Allocs/op |\n")
	b.WriteString("|---------|-----------|------:|-----------:|----------:|\n")
	lastPkg := ""
	for _, r := range sorted {
		pkgCell := ""
		if r.Pkg != lastPkg {
			pkgCell = "`" + r.Pkg + "`"
			lastPkg = r.Pkg
		}
		thr := "—"
		if r.MBs > 0 {
			thr = fmt.Sprintf("%s MB/s", trim(r.MBs))
		}
		allocs := "—"
		if r.Allocs >= 0 {
			allocs = strconv.FormatInt(r.Allocs, 10)
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n",
			pkgCell, r.Name, trim(r.NsOp), thr, allocs)
	}
	b.WriteString("\n")
	b.WriteString(meta.footer())
	return b.String()
}

// trim formats a float with up to one decimal, dropping a trailing ".0".
func trim(v float64) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0")
}
