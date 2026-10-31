// Package conflict shares the optimistic-write sentinel between store modules.
package conflict

import "errors"

var Err = errors.New("configuration changed; reload before saving")
