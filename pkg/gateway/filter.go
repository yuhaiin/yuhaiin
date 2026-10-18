package gateway

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

type FilterReport = contract.FilterReport
type urlFilter struct {
	expression *regexp.Regexp
	exception  bool
}
type filterPolicy struct {
	byHost  map[string][]urlFilter
	reports []FilterReport
}

// CompileFilters supports domain-anchored URL rules (||domain/path*), optional
// trailing ^ or |, and @@ exceptions. Options, cosmetic/scriptlet rules and
// unanchored regular expressions are rejected and counted explicitly.
func CompileFilters(lists []contract.FilterList) (*filterPolicy, error) {
	p := &filterPolicy{byHost: make(map[string][]urlFilter)}
	for _, list := range lists {
		report := FilterReport{ID: list.ID, Errors: []string{}}
		scanner := bufio.NewScanner(strings.NewReader(list.Text))
		scanner.Buffer(make([]byte, 4096), 16<<10)
		line := 0
		for scanner.Scan() {
			line++
			text := strings.TrimSpace(scanner.Text())
			if text == "" || strings.HasPrefix(text, "!") || strings.HasPrefix(text, "[") {
				continue
			}
			host, filter, err := parseURLFilter(text)
			if err != nil {
				report.Rejected++
				if len(report.Errors) < 100 {
					report.Errors = append(report.Errors, fmt.Sprintf("line %d: %s", line, err))
				}
				continue
			}
			report.Accepted++
			if list.Enabled {
				p.byHost[host] = append(p.byHost[host], filter)
			}
			if report.Accepted > 50000 {
				return nil, errors.New("filter list exceeds 50000 supported rules")
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		p.reports = append(p.reports, report)
	}
	return p, nil
}

func parseURLFilter(text string) (string, urlFilter, error) {
	f := urlFilter{}
	if strings.HasPrefix(text, "@@") {
		f.exception = true
		text = strings.TrimPrefix(text, "@@")
	}
	if strings.ContainsAny(text, "$#\r\n") || !strings.HasPrefix(text, "||") {
		return "", f, errors.New("unsupported rule: use ||domain/path* and optional @@ exception; options and cosmetic rules are unsupported")
	}
	text = strings.TrimPrefix(text, "||")
	end := false
	if strings.HasSuffix(text, "|") {
		end = true
		text = strings.TrimSuffix(text, "|")
	}
	host, path, _ := strings.Cut(text, "/")
	if strings.ContainsAny(path, "^| ") {
		return "", f, errors.New("unsupported path separator or anchor; only * and a final | are supported")
	}
	host = strings.TrimSuffix(host, "^")
	if host == "" || strings.ContainsAny(host, ":*^| ") {
		return "", f, errors.New("invalid filter domain")
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Hostname() != host {
		return "", f, errors.New("invalid filter domain")
	}
	host = hostname(host)
	var pattern strings.Builder
	pattern.WriteString("^")
	if strings.Contains(text, "/") {
		path = "/" + path
		for _, part := range strings.SplitAfter(path, "*") {
			star := strings.HasSuffix(part, "*")
			if star {
				part = strings.TrimSuffix(part, "*")
			}
			pattern.WriteString(regexp.QuoteMeta(part))
			if star {
				pattern.WriteString(".*")
			}
		}
	}
	if end {
		pattern.WriteString("$")
	}
	re, err := regexp.Compile(pattern.String())
	f.expression = re
	return host, f, err
}

func (p *filterPolicy) blocked(r *http.Request) bool {
	if p == nil {
		return false
	}
	host := hostname(r.Host)
	blocked := false
	path := r.URL.RequestURI()
	for {
		for _, f := range p.byHost[host] {
			if f.expression.MatchString(path) {
				if f.exception {
					return false
				}
				blocked = true
			}
		}
		_, rest, ok := strings.Cut(host, ".")
		if !ok {
			break
		}
		host = rest
	}
	return blocked
}
