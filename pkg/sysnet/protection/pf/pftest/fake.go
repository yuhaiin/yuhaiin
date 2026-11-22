// Package pftest simulates pfctl and the PF state it changes, so the
// protection engine and service can be tested on any platform. It models
// only what Yuhaiin uses: enable references, the main ruleset's anchor
// references (loaded from pf.conf), anchor rulesets, dry runs and counters.
// Real PF behavior is covered by the macOS integration tests.
package pftest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type Fake struct {
	mu sync.Mutex
	// Enabled is the packet filter's state; Tokens its enable references.
	Enabled bool
	Tokens  []string
	next    int
	// Main holds the main ruleset's anchor lines, as "-s rules"/"-s nat" print them.
	MainRules, MainNAT []string
	Anchors            map[string]string
	// Calls records every invocation ("pfctl -a x -f -").
	Calls []string
	// Blocked is reported as the block rule's packet counter.
	Blocked uint64
	// Missing makes every call fail as if pfctl did not exist.
	Missing bool
	// Fail makes calls containing a key fail with its error.
	Fail map[string]error
	// OnCall runs before each call (for checking ordering against files).
	OnCall func(call string)
}

func New() *Fake { return &Fake{Anchors: map[string]string{}, Fail: map[string]error{}} }

func (f *Fake) CallLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Calls...)
}

// Loaded returns the rules loaded into anchor.
func (f *Fake) Loaded(anchor string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Anchors[anchor]
}

// SetLoaded replaces an anchor's rules (another program changing them).
func (f *Fake) SetLoaded(anchor, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if text == "" {
		delete(f.Anchors, anchor)
	} else {
		f.Anchors[anchor] = text
	}
}

// ForceDisable simulates "pfctl -d" by another program.
func (f *Fake) ForceDisable() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Enabled, f.Tokens = false, nil
}

// LoadMain simulates another program loading a main ruleset.
func (f *Fake) LoadMain(rules, nat []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.MainRules, f.MainNAT = rules, nat
}

func (f *Fake) Run(_ context.Context, stdin, name string, args ...string) (string, error) {
	call := "pfctl " + strings.Join(args, " ")
	if !strings.HasSuffix(name, "pfctl") {
		call = name + " " + strings.Join(args, " ")
	}
	if f.OnCall != nil {
		f.OnCall(call)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, call)
	if f.Missing {
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	for key, err := range f.Fail {
		if strings.Contains(call, key) {
			return "pfctl: " + err.Error(), err
		}
	}
	anchor := ""
	rest := args
	if len(rest) >= 2 && rest[0] == "-a" {
		anchor, rest = rest[1], rest[2:]
	}
	dry := false
	if len(rest) > 0 && rest[0] == "-n" {
		dry, rest = true, rest[1:]
		if len(rest) >= 2 && rest[0] == "-a" {
			anchor, rest = rest[1], rest[2:]
		}
	}
	switch {
	case len(rest) == 2 && rest[0] == "-s" && rest[1] == "info":
		return fmt.Sprintf("Status: %s for 0 days 00:00:01           Debug: Urgent\n", map[bool]string{true: "Enabled", false: "Disabled"}[f.Enabled]), nil
	case len(rest) == 2 && rest[0] == "-s" && rest[1] == "References":
		var b strings.Builder
		b.WriteString("TOKENS:\nPID      Process Name                TOKEN                 TIMESTAMP\n")
		for _, t := range f.Tokens {
			fmt.Fprintf(&b, "1234     pfctl                       %s      0 days 00:00:01\n", t)
		}
		return b.String(), nil
	case anchor == "" && len(rest) == 2 && rest[0] == "-s" && rest[1] == "rules":
		return strings.Join(f.MainRules, "\n") + "\n", nil
	case anchor == "" && len(rest) == 2 && rest[0] == "-s" && rest[1] == "nat":
		return strings.Join(f.MainNAT, "\n") + "\n", nil
	case anchor != "" && len(rest) == 2 && rest[0] == "-s" && rest[1] == "Tables":
		var b strings.Builder
		for name := range f.tables(anchor) {
			b.WriteString("--a-r-- " + name + "\n")
		}
		return b.String(), nil
	case anchor != "" && len(rest) == 4 && rest[0] == "-t" && rest[2] == "-T" && rest[3] == "show":
		entries, ok := f.tables(anchor)[rest[1]]
		if !ok {
			return "pfctl: Table does not exist.", errors.New("exit status 1")
		}
		var b strings.Builder
		for _, e := range entries {
			b.WriteString("   " + e + "\n")
		}
		return b.String(), nil
	case anchor != "" && len(rest) >= 2 && rest[len(rest)-2] == "-s":
		verbose := len(rest) == 3 && rest[0] == "-v"
		return f.show(anchor, rest[len(rest)-1], verbose), nil
	case len(rest) == 2 && rest[0] == "-f":
		text := stdin
		if rest[1] != "-" {
			data, err := os.ReadFile(rest[1])
			if err != nil {
				return "pfctl: cannot open the main config file", err
			}
			text = string(data)
		}
		if strings.Contains(text, "INVALID") {
			return "stdin:1: syntax error", errors.New("exit status 1")
		}
		if dry {
			return "", nil
		}
		if anchor != "" {
			f.Anchors[anchor] = text
			return "", nil
		}
		f.loadMain(text)
		return "pfctl: Use of -f option, could result in flushing of rules\n", nil
	case len(rest) == 2 && rest[0] == "-F":
		if anchor == "" {
			return "", errors.New("fake pfctl refuses to flush the main ruleset")
		}
		if rest[1] == "rules" || rest[1] == "all" {
			delete(f.Anchors, anchor)
		}
		return "", nil
	case len(rest) == 1 && rest[0] == "-E":
		f.next++
		token := fmt.Sprintf("%d", 18000000000000000000+uint64(f.next))
		f.Tokens = append(f.Tokens, token)
		f.Enabled = true
		return "pf enabled\nToken : " + token + "\n", nil
	case len(rest) == 2 && rest[0] == "-X":
		for i, t := range f.Tokens {
			if t == rest[1] {
				f.Tokens = append(f.Tokens[:i], f.Tokens[i+1:]...)
				if len(f.Tokens) == 0 {
					f.Enabled = false
				}
				return "pf disabled\n", nil
			}
		}
		return "pfctl: invalid token", errors.New("exit status 1")
	case len(rest) == 1 && rest[0] == "-d":
		f.Enabled, f.Tokens = false, nil
		return "pf disabled\n", nil
	}
	return "", fmt.Errorf("fake pfctl: unsupported call %q", call)
}

func (f *Fake) loadMain(text string) {
	f.MainRules, f.MainNAT = nil, nil
	for line := range strings.SplitSeq(text, "\n") {
		code, _, _ := strings.Cut(line, "#")
		fields := strings.Fields(code)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "scrub-anchor":
			f.MainRules = append(f.MainRules, "scrub-anchor "+fields[1]+" all fragment reassemble")
		case "anchor":
			f.MainRules = append(f.MainRules, "anchor "+fields[1]+" all")
		case "nat-anchor":
			f.MainNAT = append(f.MainNAT, "nat-anchor "+fields[1]+" all")
		}
	}
}

func (f *Fake) show(anchor, what string, verbose bool) string {
	text := f.Anchors[anchor]
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		keyword, _, _ := strings.Cut(line, " ")
		filter := keyword == "pass" || keyword == "block"
		if (what == "rules" && !filter) || (what == "nat" && keyword != "nat") {
			continue
		}
		b.WriteString(line + "\n")
		if verbose {
			var packets, states uint64
			if strings.HasPrefix(line, "block") {
				packets = f.Blocked
			}
			if strings.Contains(line, "yuhaiin-own-") {
				states = 2
			}
			fmt.Fprintf(&b, "  [ Evaluations: 10        Packets: %-10d Bytes: %-10d States: %-6d]\n", packets, packets*60, states)
			b.WriteString("  [ Inserted: uid 0 pid 1 State Creations: 0     ]\n")
		}
	}
	return b.String()
}

// tables returns the tables defined in an anchor's rules ("table <name>
// const { a, b }").
func (f *Fake) tables(anchor string) map[string][]string {
	out := map[string][]string{}
	for line := range strings.SplitSeq(f.Anchors[anchor], "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "table <")
		if !ok {
			continue
		}
		name, rest, _ := strings.Cut(rest, ">")
		_, body, _ := strings.Cut(rest, "{")
		body, _, _ = strings.Cut(body, "}")
		var entries []string
		for e := range strings.SplitSeq(body, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
		out[name] = entries
	}
	return out
}
