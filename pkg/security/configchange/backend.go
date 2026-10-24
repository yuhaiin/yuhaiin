package configchange

import (
	"context"
	"encoding/json/jsontext"
)

// Backend connects an existing configuration module to the optional management
// workflow. Its mutations must use Begin, RecordValues and Commit in the
// resource's own database; Apply must prepare activation before persistence.
type Backend interface {
	Journal() *Journal
	Enable(context.Context) error
	Stage(context.Context, string, string, string, jsontext.Value) (Change, error)
	Apply(context.Context, Document, bool) error
	Activation(context.Context, Change) (string, error)
}
