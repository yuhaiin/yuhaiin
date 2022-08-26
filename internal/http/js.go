package simplehttp

import _ "embed"

//go:embed toast.html
var toastHTML []byte

//go:embed node.js
var nodeJS []byte

//go:embed sub.js
var subJS []byte

//go:embed statistic.js
var statisticJS []byte

//go:embed http.js
var metaJS []byte

//go:embed config.js
var configJS []byte
