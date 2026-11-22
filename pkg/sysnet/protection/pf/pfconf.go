package pf

import (
	"strings"
)

// The main ruleset evaluates Yuhaiin's anchors through two lines that carry
// this marker. Only marked lines are ever removed; an equivalent line a user
// added by hand counts as registered and is left alone.
const confMarker = "# managed by Yuhaiin (io.github.yuhaiin)"

var (
	natLine    = `nat-anchor "` + Anchor + `/*" ` + confMarker
	filterLine = `anchor "` + Anchor + `/*" ` + confMarker
)

type confLine struct {
	start, end int // physical line range [start, end)
	keyword    string
	managed    bool
	nat        bool // a nat-anchor for Yuhaiin
	filter     bool // an anchor for Yuhaiin
}

var (
	translationKeywords = map[string]bool{"nat-anchor": true, "rdr-anchor": true, "binat-anchor": true, "nat": true, "rdr": true, "binat": true, "no": true}
	filterKeywords      = map[string]bool{"anchor": true, "pass": true, "block": true, "antispoof": true}
	// dummynet rules follow translation and precede filter rules on macOS.
	dummynetKeywords = map[string]bool{"dummynet-anchor": true, "dummynet": true}
)

// parseConf splits pf.conf into logical lines (joining "\" continuations)
// and classifies each by its first word. Comments and blank lines have no
// keyword.
func parseConf(conf string) ([]string, []confLine) {
	physical := strings.Split(conf, "\n")
	var out []confLine
	for i := 0; i < len(physical); {
		start := i
		var logical strings.Builder
		for {
			line := physical[i]
			i++
			if strings.HasSuffix(line, `\`) && i < len(physical) {
				logical.WriteString(strings.TrimSuffix(line, `\`))
				logical.WriteByte(' ')
				continue
			}
			logical.WriteString(line)
			break
		}
		text := logical.String()
		code := text
		if idx := strings.IndexByte(code, '#'); idx >= 0 {
			code = code[:idx]
		}
		fields := strings.Fields(code)
		cl := confLine{start: start, end: i, managed: strings.Contains(text, confMarker)}
		if len(fields) > 0 {
			cl.keyword = fields[0]
			if len(fields) > 1 && strings.Trim(fields[1], `"`) == Anchor+"/*" {
				cl.nat = cl.keyword == "nat-anchor"
				cl.filter = cl.keyword == "anchor"
			}
		}
		out = append(out, cl)
	}
	return physical, out
}

// ConfRegistration is what a pf.conf already contains.
type ConfRegistration struct {
	// Filter and NAT report lines evaluating Yuhaiin's anchors, managed or not.
	Filter, NAT bool
	// Managed reports lines carrying the marker.
	Managed bool
}

// Registered inspects conf.
func Registered(conf string) ConfRegistration {
	_, lines := parseConf(conf)
	var r ConfRegistration
	for _, l := range lines {
		r.Filter = r.Filter || l.filter
		r.NAT = r.NAT || l.nat
		r.Managed = r.Managed || l.managed
	}
	return r
}

// Register returns conf with Yuhaiin's anchors evaluated. Existing content
// is kept byte for byte; only the managed lines are added:
//
//   - nat-anchor right after the last translation rule (or, without one,
//     before the first dummynet or filter rule), as PF requires translation
//     before filtering;
//   - anchor before the first filter rule, so the kill switch is evaluated
//     before other filter rules can pass traffic with "quick".
//
// withNAT false registers only the filter anchor (a fallback when a
// customized pf.conf does not accept the nat-anchor where it is placed).
// Already registered rule types are not added again.
func Register(conf string, withNAT bool) (string, bool) {
	physical, lines := parseConf(conf)
	reg := Registered(conf)
	needNAT := withNAT && !reg.NAT
	needFilter := !reg.Filter
	if !needNAT && !needFilter {
		return conf, false
	}
	natAt, filterAt, firstLater := -1, -1, -1
	for _, l := range lines {
		switch {
		case translationKeywords[l.keyword]:
			if filterAt < 0 {
				natAt = l.end
			}
		case filterKeywords[l.keyword]:
			if filterAt < 0 {
				filterAt = l.start
			}
			if firstLater < 0 {
				firstLater = l.start
			}
		case dummynetKeywords[l.keyword]:
			if firstLater < 0 {
				firstLater = l.start
			}
		}
	}
	end := len(physical)
	// A trailing newline yields an empty last element: insert before it.
	if end > 0 && physical[end-1] == "" {
		end--
	}
	if natAt < 0 {
		natAt = firstLater
	}
	if natAt < 0 {
		natAt = end
	}
	if filterAt < 0 {
		filterAt = end
	}
	insert := map[int][]string{}
	if needNAT {
		insert[natAt] = append(insert[natAt], natLine)
	}
	if needFilter {
		insert[filterAt] = append(insert[filterAt], filterLine)
	}
	var out []string
	for i := 0; i <= len(physical); i++ {
		out = append(out, insert[i]...)
		if i < len(physical) {
			out = append(out, physical[i])
		}
	}
	result := strings.Join(out, "\n")
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	return result, true
}

// Unregister removes the managed lines and nothing else.
func Unregister(conf string) (string, bool) {
	physical, lines := parseConf(conf)
	drop := map[int]bool{}
	for _, l := range lines {
		if l.managed && (l.nat || l.filter) {
			for i := l.start; i < l.end; i++ {
				drop[i] = true
			}
		}
	}
	if len(drop) == 0 {
		return conf, false
	}
	var out []string
	for i, line := range physical {
		if !drop[i] {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n"), true
}
