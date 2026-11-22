package mcpserver

import (
	"reflect"
	"slices"
	"strings"
	"time"
)

// schemaFor derives the JSON Schema of a request DTO from its Go type, so the
// MCP tool schemas of configuration tools never drift from the HTTP API
// contracts. Named struct types become $defs, which also handles recursive
// types (protocol chains, rule expressions, gateway conditions). Objects are
// closed: unknown members are rejected by the schema and by strict decoding.
func schemaFor[T any]() map[string]any {
	g := &schemaGenerator{defs: map[string]any{}}
	root := g.structSchema(reflect.TypeFor[T]())
	if len(g.defs) > 0 {
		root["$defs"] = g.defs
	}
	return root
}

type schemaGenerator struct {
	defs map[string]any
}

var timeType = reflect.TypeFor[time.Time]()

func defName(t reflect.Type) string {
	pkg := t.PkgPath()
	return pkg[strings.LastIndex(pkg, "/")+1:] + "." + t.Name()
}

func (g *schemaGenerator) schema(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == timeType:
		return map[string]any{"type": "string", "format": "date-time"}
	case t.Kind() == reflect.Struct && t.Name() != "":
		name := defName(t)
		if _, ok := g.defs[name]; !ok {
			g.defs[name] = true // placeholder breaks cycles
			g.defs[name] = g.structSchema(t)
		}
		return map[string]any{"$ref": "#/$defs/" + name}
	}
	switch t.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer", "minimum": 0}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": g.schema(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.schema(t.Elem())}
	case reflect.Struct:
		return g.structSchema(t)
	default:
		return map[string]any{}
	}
}

func (g *schemaGenerator) structSchema(t reflect.Type) map[string]any {
	properties := map[string]any{}
	g.fields(t, properties)
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if variants := unionVariants(t); len(variants) > 1 {
		if typeSchema, ok := properties["type"].(map[string]any); ok {
			typeSchema["enum"] = variants
		}
		schema["description"] = "Tagged union: set type to one of the variant property names and fill only that property."
	}
	return schema
}

// fields collects the JSON members of t, inlining embedded structs the way
// encoding/json does.
func (g *schemaGenerator) fields(t reflect.Type, properties map[string]any) {
	for field := range t.Fields() {
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, options, _ := strings.Cut(tag, ",")
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				g.fields(embedded, properties)
				continue
			}
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		schema := g.schema(field.Type)
		// A nil pointer without omitzero/omitempty is encoded as null, so a
		// value read from the API must validate when it is sent back.
		if field.Type.Kind() == reflect.Pointer && !strings.Contains(options, "omitzero") && !strings.Contains(options, "omitempty") {
			schema = map[string]any{"anyOf": []any{schema, map[string]any{"type": "null"}}}
		}
		if secret := field.Tag.Get("secret"); secret != "" {
			schema = map[string]any{"allOf": []any{schema}, "description": "Secret; a redacted value keeps the stored secret."}
		}
		properties[name] = schema
	}
}

// unionVariants returns the JSON names of the optional struct members of a
// tagged union, i.e. a struct with a string "type" member whose value names
// the single populated variant.
func unionVariants(t reflect.Type) []string {
	var variants []string
	hasType := false
	for field := range t.Fields() {
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "type" && field.Type.Kind() == reflect.String {
			hasType = true
			continue
		}
		// Variants are optional objects that are omitted when unset.
		optional := strings.Contains(options, "omitzero") || strings.Contains(options, "omitempty")
		kind := field.Type.Kind()
		if optional && (kind == reflect.Pointer || kind == reflect.Slice) && field.Type.Elem().Kind() == reflect.Struct && name != "" && name != "-" {
			variants = append(variants, name)
		}
	}
	if !hasType {
		return nil
	}
	slices.Sort(variants)
	return variants
}
