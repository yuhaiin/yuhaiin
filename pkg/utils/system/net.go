package system

import (
	"errors"
)

// Maybe rawURL is of the form scheme:path.
// (Scheme must be [a-zA-Z][a-zA-Z0-9+.-]*)
// If so, return scheme, path; else return "", rawURL.
//
// copy from [net/url.getScheme]
func GetScheme(rawURL string) (scheme, path string, err error) {
	for i := range len(rawURL) {
		c := rawURL[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		// do nothing
		case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return "", rawURL, nil
			}
		case c == ':':
			if i == 0 {
				return "", "", errors.New("missing protocol scheme")
			}
			return rawURL[:i], rawURL[i+1:], nil
		default:
			// we have encountered an invalid character,
			// so there is no valid scheme
			return "", rawURL, nil
		}
	}
	return "", rawURL, nil
}

var UserAgentLength = len(UserAgents)

var UserAgents = []string{
	"",
	"curl/7.1.2",
	"curl/7.2.3",
	"curl/7.1.3",
	"curl/7.1.4",
	"curl/7.1.5",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/99.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/101.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/102.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/99.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/101.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/102.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.6743.241 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.6743.241 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.6743.241 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.6743.241 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:100.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.3325.162 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3239.83 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.3239.83 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.3239.83 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.3239.83 Mobile Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.2272.89 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.2272.89 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.2272.89 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.2272.89 Safari/537.36",
}

/*
This was documented in the DNS specification, RFC 1034, way back in 1987

Since a complete domain name ends with the root label, this leads to a
printed form which ends in a dot.  We use this property to distinguish between:

   - a character string which represents a complete domain name
     (often called "absolute").  For example, "poneria.ISI.EDU."

   - a character string that represents the starting labels of a
     domain name which is incomplete, and should be completed by
     local software using knowledge of the local domain (often
     called "relative").  For example, "poneria" used in the
     ISI.EDU domain.
*/

// AbsDomain a character string which represents a complete domain name
// (often called "absolute").  For example, "poneria.ISI.EDU."
func AbsDomain(domain string) string {
	if len(domain) == 0 {
		return "."
	}

	if domain[len(domain)-1] == '.' {
		return domain
	}

	return domain + "."
}

// RelDomain a character string that represents the starting labels of a
// domain name which is incomplete, and should be completed by
// local software using knowledge of the local domain (often
// called "relative").  For example, "poneria" used in the
// ISI.EDU domain.
func RelDomain(domain string) string {
	if len(domain) == 0 {
		return ""
	}

	if domain[len(domain)-1] == '.' {
		return domain[:len(domain)-1]
	}

	return domain
}
