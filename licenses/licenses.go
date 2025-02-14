package licenses

import (
	"bufio"
	"bytes"
	_ "embed"
	"regexp"
)

//go:embed yuhaiin.md
var yuhaiin []byte

//go:embed android.md
var android []byte

var reg = regexp.MustCompile(`- \[(.*)\]\((.*)\) \(\[(.*)\]\((.*)\)\)`)

type License struct {
	Name       string
	URL        string
	License    string
	LicenseURL string
}

func FindLicense(b string) (License, bool) {
	if !reg.MatchString(b) {
		return License{}, false
	}

	subs := reg.FindAllStringSubmatch(b, -1)
	if len(subs) <= 0 || len(subs[0]) < 5 {
		return License{}, false
	}

	ll := subs[0][1:]

	return License{
		Name:       ll[0],
		URL:        ll[1],
		License:    ll[2],
		LicenseURL: ll[3],
	}, true
}

func Yuhaiin() []License {
	return getLicenses(yuhaiin)
}

func Android() []License {
	return getLicenses(android)
}

func getLicenses(b []byte) []License {
	scan := bufio.NewScanner(bytes.NewBuffer(b))
	var licenses []License
	for scan.Scan() {
		license, ok := FindLicense(scan.Text())
		if !ok {
			continue
		}
		licenses = append(licenses, license)
	}
	return licenses
}
