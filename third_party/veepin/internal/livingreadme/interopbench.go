package livingreadme

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// iperfMarker is the token an interop benchmark test prints (via t.Log) to carry
// a throughput measurement out through `go test -json`. The line that follows it
// is "<test-name> <bits-per-second>", so a single test run feeds both the interop
// matrix (pass/fail) and the interop-benchmark table (speed).
const iperfMarker = "livingreadme:iperf3"

// iperfFailedMarker is logged instead when a test tried to measure and could
// not. Distinguishing the two is the whole point: a cell that was never measured
// and a cell whose measurement broke are different facts, and rendering both as
// an em dash presented a broken measurement as a deliberate omission.
//
// Note it has iperfMarker as a prefix, so anything matching must test for this
// one first.
const iperfFailedMarker = "livingreadme:iperf3-failed"

// IperfLine formats the marker line a test logs after measuring a tunnel. Keeping
// the format in this package means the producer (the interop harness) and the
// consumer (ParseThroughput) cannot drift apart.
func IperfLine(testName string, bitsPerSec float64) string {
	return fmt.Sprintf("%s %s %.0f", iperfMarker, testName, bitsPerSec)
}

// IperfFailedLine formats the marker a test logs when it attempted a measurement
// that did not produce a number.
func IperfFailedLine(testName string) string {
	return fmt.Sprintf("%s %s", iperfFailedMarker, testName)
}

// Measurement is one cell's throughput outcome. The zero value means the test
// never tried, which is different from Failed: the first is a cell iperf3 does
// not apply to, the second is a cell where it applies and did not work.
type Measurement struct {
	BitsPerSec float64
	Failed     bool
}

// Throughput maps an interop test name to its measurement outcome. A name absent
// from the map was never measured at all.
type Throughput map[string]Measurement

// ParseThroughput reads `go test -json` output and extracts every iperf3 marker
// a test logged. Markers arrive inside "output" events, prefixed by go test's
// "    file.go:NN: " framing, so it scans each output payload for the token
// rather than matching a whole line.
func ParseThroughput(jsonOut string) Throughput {
	out := Throughput{}
	sc := bufio.NewScanner(strings.NewReader(jsonOut))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			// Tolerate a raw (non-JSON) stream too: parse the marker directly.
			recordMarker(out, line)
			continue
		}
		var ev struct {
			Output string `json:"Output"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		recordMarker(out, ev.Output)
	}
	return out
}

// recordMarker parses one text fragment for an iperf3 marker and, if found,
// records it. A successful measurement keeps the highest value seen for that
// test (a test may measure once, but a retry that logs twice should not lose the
// successful number to a later 0), and a success always beats a failure for the
// same reason — a retry that worked is the truth about the cell.
//
// The failed marker is matched first because the successful one is a prefix of
// it.
func recordMarker(out Throughput, text string) {
	if _, after, found := strings.Cut(text, iperfFailedMarker); found {
		fields := strings.Fields(after)
		if len(fields) < 1 {
			return
		}
		if prev, seen := out[fields[0]]; seen && prev.BitsPerSec > 0 {
			return // a real measurement already stands for this cell
		}
		out[fields[0]] = Measurement{Failed: true}
		return
	}

	_, after, found := strings.Cut(text, iperfMarker)
	if !found {
		return
	}
	fields := strings.Fields(after)
	if len(fields) < 2 {
		return
	}
	bps, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return
	}
	if bps > out[fields[0]].BitsPerSec {
		out[fields[0]] = Measurement{BitsPerSec: bps}
	}
}

// benchCell renders one interop-benchmark cell, distinguishing three states that
// used to collapse into one em dash:
//
//   - "—" — iperf3 does not apply here. Either the cell has no test at all, or
//     its test measures nothing (a datagram-forwarding cell, or a peer with no
//     bindable tunnel address).
//   - "✗" — it does apply, was attempted, and did not produce a number. A
//     measurement that is broken rather than absent.
//   - a rate — the measurement.
func benchCell(c interopCell, tp Throughput) string {
	// Scan the whole cell rather than reading Tests[0].
	//
	// The convention is that a cell's first test is the one that calls
	// runInteropBench, and every cell in the manifest honours it today -- so
	// this changes no rendered value. What it removes is a positional trap:
	// inserting a test at the front of a cell used to blank its throughput
	// column silently, reporting a measured tunnel as one iperf3 does not apply
	// to. That is exactly how the pq- cells' numbers went missing while they
	// were still folded into their base protocols' rows.
	//
	// Order still decides which number wins when several tests measured, and
	// order is the convention's priority order: the plain cell first, its
	// variants after. So the plain cell's figure is preferred wherever it
	// exists, and a variant's is used only when the plain one measured nothing.
	attempted := false
	for _, name := range c.Tests {
		m, ok := tp[name]
		if !ok {
			continue
		}
		attempted = true
		if !m.Failed && m.BitsPerSec > 0 {
			return formatBits(m.BitsPerSec)
		}
	}
	if attempted {
		return "✗"
	}
	return "—"
}

// RenderInteropBench renders the interop throughput table: the same protocol ×
// direction shape as the interop matrix, each cell carrying an iperf3 figure
// measured across that live tunnel. Cells without a measurement show an em dash.
func RenderInteropBench(tp Throughput, meta Meta) string {
	var b strings.Builder
	b.WriteString("| Protocol   | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |\n")
	b.WriteString("|------------|----------------------------:|----------------------------:|-----------------------:|\n")
	for _, row := range interopMatrix {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			row.Protocol,
			benchCell(row.Client, tp),
			benchCell(row.Server, tp),
			benchCell(row.Self, tp),
		)
	}
	b.WriteString("\n")
	b.WriteString(meta.footer())
	return b.String()
}

// formatBits renders a bits-per-second rate in the largest unit that keeps the
// value >= 1, with three significant figures, e.g. 1.94 Gbit/s or 850 Mbit/s.
func formatBits(bps float64) string {
	switch {
	case bps >= 1e9:
		return trimSig(bps/1e9) + " Gbit/s"
	case bps >= 1e6:
		return trimSig(bps/1e6) + " Mbit/s"
	case bps >= 1e3:
		return trimSig(bps/1e3) + " kbit/s"
	default:
		return trimSig(bps) + " bit/s"
	}
}

// trimSig formats a value to three significant figures, dropping a trailing
// ".0"/".00" so whole numbers read cleanly.
func trimSig(v float64) string {
	prec := 2
	switch {
	case v >= 100:
		prec = 0
	case v >= 10:
		prec = 1
	}
	s := strconv.FormatFloat(v, 'f', prec, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
	}
	return s
}
