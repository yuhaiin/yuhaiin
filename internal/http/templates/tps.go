package templates

import (
	"embed"
)

//go:embed *
var Pages embed.FS

const (
	FRAME = "http.html"

	GROUP_LIST = "grouplist.html"
	ROOT       = "root.html"
	STATISTIC  = "statistic.html"
	SUB        = "sub.html"
	NEW_NODE   = "newnode.html"
	EMPTY_BODY = "body.html"
	CONFIG     = "config.html"
)
