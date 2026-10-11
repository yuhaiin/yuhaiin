// Package capture holds captured peer traffic and the machinery to replay it
// against veepin's own codecs, offline and without Docker.
//
// The interop matrix in tests/interop is the load-bearing evidence in this
// project, and it is also the slowest thing in it: Docker, pinned peer images,
// fifteen-minute timeouts, path filters. The evidence that matters most is
// therefore the evidence a developer checks least often. A corpus captures one
// cell's wire traffic once and lets `go test ./...` replay it in milliseconds.
//
// # What a replay proves, and what it does not
//
// A replay is not a substitute for the live cell, and nothing here should ever
// be allowed to read as one. A recording pins the peer *as it was on the day it
// was captured*: it cannot notice that strongSwan 6.1 changed a default, that a
// new cipher appeared in a proposal, or that the peer stopped tolerating
// something it used to. Trusting a corpus as current would be the most
// sophisticated instance yet of the exact failure this repository keeps finding
// — a green test that proves the two halves agree with a memory rather than
// with a peer.
//
// What it does prove is the half a unit test cannot reach on its own: that
// veepin's parser accepts bytes a real implementation actually emitted, and —
// where the codec is a Marshal/Parse pair — that veepin's *encoder* produces
// those same bytes back. That is an oracle written by somebody else, which is
// the only kind worth having for the mutually-consistent-bug class.
//
// # The file format
//
// Text, and deliberately so: a golden corpus is only useful if a human can read
// the diff when it changes. Metadata as `key = value` lines, free comments, then
// one record per captured message:
//
//	# strongSwan speaks first with a cookie-less IKE_SA_INIT.
//	> peer ike_sa_init_response
//	2a3b4c5d...
//
// Hex is wrapped at [hexWrap] octets per line. Records keep capture order, which
// for a control exchange is the exchange itself.
package capture

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Direction says who put a record's bytes on the wire. The distinction matters
// because the two are worth different assertions: a peer record is an oracle,
// and a veepin record is only a witness to what veepin did that day.
type Direction string

const (
	// FromPeer is traffic the third-party implementation sent.
	FromPeer Direction = "peer"
	// FromVeepin is traffic veepin sent, kept so an exchange reads in order.
	FromVeepin Direction = "veepin"
)

// hexWrap is the octets per hex line. 32 keeps a line inside 64 columns, so a
// record diffs one readable row at a time rather than as one enormous string.
const hexWrap = 32

// Record is one captured message.
type Record struct {
	Dir   Direction
	Label string
	Bytes []byte
	// Note is the free comment written immediately above the record, if any.
	// It survives a round trip so the reasoning attached to a capture is not
	// lost the first time the corpus is regenerated.
	Note string
}

// Corpus is one cell's capture.
type Corpus struct {
	// Cell names the compose file this came from, so a reader can rerun the
	// live cell that produced it.
	Cell string
	// Peer names the implementation and its version. A corpus whose peer is
	// unidentified cannot be reasoned about later, so [Corpus.Marshal] refuses
	// to write one.
	Peer string
	// Captured is the ISO date of capture — the corpus's own expiry warning.
	Captured string
	// Notes are free lines written above the metadata block.
	Notes []string

	Records []Record
}

var (
	errNoPeer     = errors.New("capture: corpus has no peer, so nothing later can tell what it is evidence of")
	errNoCell     = errors.New("capture: corpus has no cell, so nothing later can rerun what produced it")
	errNoCaptured = errors.New("capture: corpus has no capture date, so nothing later can tell how stale it is")
)

// Marshal renders the corpus in the text format described on the package.
//
// It refuses to write a corpus missing any of cell, peer or capture date.
// Those three are what stop a recording from quietly becoming folklore, and a
// corpus is written once and read for years — the moment to require them is
// while the machine that knows the answers is still running.
func (c *Corpus) Marshal() ([]byte, error) {
	switch {
	case c.Peer == "":
		return nil, errNoPeer
	case c.Cell == "":
		return nil, errNoCell
	case c.Captured == "":
		return nil, errNoCaptured
	}

	var b strings.Builder
	b.WriteString("# veepin replay corpus. Captured peer traffic, replayed offline.\n")
	b.WriteString("#\n")
	b.WriteString("# This is NOT a substitute for the live interop cell. It pins the peer as it\n")
	b.WriteString("# was on the capture date below and can never notice that the peer changed.\n")
	b.WriteString("# Regenerate it from the cell; do not hand-edit it to make a test pass.\n")
	for _, n := range c.Notes {
		b.WriteString("# ")
		b.WriteString(n)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "cell = %s\n", c.Cell)
	fmt.Fprintf(&b, "peer = %s\n", c.Peer)
	fmt.Fprintf(&b, "captured = %s\n", c.Captured)

	for _, r := range c.Records {
		b.WriteString("\n")
		if r.Note != "" {
			for line := range strings.SplitSeq(r.Note, "\n") {
				b.WriteString("# ")
				b.WriteString(line)
				b.WriteString("\n")
			}
		}
		fmt.Fprintf(&b, "> %s %s\n", r.Dir, r.Label)
		enc := hex.EncodeToString(r.Bytes)
		for i := 0; i < len(enc); i += hexWrap * 2 {
			end := min(i+hexWrap*2, len(enc))
			b.WriteString(enc[i:end])
			b.WriteString("\n")
		}
	}
	return []byte(b.String()), nil
}

// Parse reads the text format back.
//
// It is strict about everything it can be strict about. A corpus is consulted
// by tests that fail loudly when bytes differ, so a parser that guessed at a
// malformed line would turn a corrupt file into a mysterious byte mismatch
// several frames later instead of an error naming the line.
func Parse(data []byte) (*Corpus, error) {
	c := &Corpus{}
	var (
		cur     *Record
		pending []string
		inMeta  = true
	)
	flush := func() {
		if cur != nil {
			c.Records = append(c.Records, *cur)
			cur = nil
		}
	}

	for i, raw := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			continue

		case strings.HasPrefix(line, "#"):
			text := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			// The banner this package writes is regenerated on every Marshal;
			// keeping it would double it on each round trip.
			if isBanner(text) {
				continue
			}
			pending = append(pending, text)

		case strings.HasPrefix(line, ">"):
			flush()
			inMeta = false
			fields := strings.Fields(strings.TrimPrefix(line, ">"))
			if len(fields) != 2 {
				return nil, fmt.Errorf("capture: line %d: want `> <peer|veepin> <label>`, got %q", lineNo, line)
			}
			dir := Direction(fields[0])
			if dir != FromPeer && dir != FromVeepin {
				return nil, fmt.Errorf("capture: line %d: unknown direction %q", lineNo, fields[0])
			}
			cur = &Record{Dir: dir, Label: fields[1], Note: strings.Join(pending, "\n")}
			pending = nil

		case inMeta:
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return nil, fmt.Errorf("capture: line %d: want `key = value`, got %q", lineNo, line)
			}
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			switch key {
			case "cell":
				c.Cell = value
			case "peer":
				c.Peer = value
			case "captured":
				c.Captured = value
			default:
				return nil, fmt.Errorf("capture: line %d: unknown metadata key %q", lineNo, key)
			}
			if len(pending) > 0 {
				c.Notes = append(c.Notes, pending...)
				pending = nil
			}

		default:
			b, err := hex.DecodeString(line)
			if err != nil {
				return nil, fmt.Errorf("capture: line %d: %w", lineNo, err)
			}
			cur.Bytes = append(cur.Bytes, b...)
		}
	}
	flush()
	if len(pending) > 0 {
		c.Notes = append(c.Notes, pending...)
	}

	switch {
	case c.Peer == "":
		return nil, errNoPeer
	case c.Cell == "":
		return nil, errNoCell
	case c.Captured == "":
		return nil, errNoCaptured
	}
	return c, nil
}

// isBanner reports whether a comment line is one Marshal writes itself.
func isBanner(text string) bool {
	for _, p := range bannerPrefixes {
		if strings.HasPrefix(text, p) {
			return true
		}
	}
	return text == ""
}

var bannerPrefixes = []string{
	"veepin replay corpus.",
	"This is NOT a substitute",
	"was on the capture date",
	"Regenerate it from the cell",
}

// Find returns the first record with the given label.
func (c *Corpus) Find(label string) (Record, bool) {
	for _, r := range c.Records {
		if r.Label == label {
			return r, true
		}
	}
	return Record{}, false
}

// PeerRecords returns only what the third-party implementation sent — the
// records that are an oracle rather than a witness.
func (c *Corpus) PeerRecords() []Record {
	var out []Record
	for _, r := range c.Records {
		if r.Dir == FromPeer {
			out = append(out, r)
		}
	}
	return out
}

// Labels returns the record labels, sorted, for a test that wants to assert a
// corpus still contains what it was captured for.
func (c *Corpus) Labels() []string {
	out := make([]string, 0, len(c.Records))
	for _, r := range c.Records {
		out = append(out, r.Label)
	}
	slices.Sort(out)
	return out
}
