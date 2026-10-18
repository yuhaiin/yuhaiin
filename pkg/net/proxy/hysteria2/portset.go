package hysteria2

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type portRange struct{ Start, End uint16 }
type portRanges []portRange
type hopInterval struct{ Min, Max time.Duration }

// parseHopPorts returns validated, normalized inclusive ranges.
func parseHopPorts(s string) (portRanges, error) {
	if s == "" {
		return nil, fmt.Errorf("hysteria2: empty hopping ports")
	}
	var result portRanges
	for part := range strings.SplitSeq(s, ",") {
		values := strings.Split(part, "-")
		if len(values) > 2 {
			return nil, fmt.Errorf("hysteria2: invalid port range %q", part)
		}
		start, err := strconv.ParseUint(values[0], 10, 16)
		if err != nil || start == 0 {
			return nil, fmt.Errorf("hysteria2: invalid port %q", values[0])
		}
		end := start
		if len(values) == 2 {
			end, err = strconv.ParseUint(values[1], 10, 16)
			if err != nil || end == 0 {
				return nil, fmt.Errorf("hysteria2: invalid port %q", values[1])
			}
		}
		if end < start {
			start, end = end, start
		}
		result = append(result, portRange{uint16(start), uint16(end)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Start < result[j].Start })
	merged := result[:0]
	for _, r := range result {
		if len(merged) > 0 && uint32(r.Start) <= uint32(merged[len(merged)-1].End)+1 {
			if r.End > merged[len(merged)-1].End {
				merged[len(merged)-1].End = r.End
			}
		} else {
			merged = append(merged, r)
		}
	}
	return merged, nil
}

func (r portRanges) Ports() []uint16 {
	n := 0
	for _, v := range r {
		n += int(v.End) - int(v.Start) + 1
	}
	p := make([]uint16, 0, n)
	for _, v := range r {
		for i := uint32(v.Start); i <= uint32(v.End); i++ {
			p = append(p, uint16(i))
		}
	}
	return p
}
