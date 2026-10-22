package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestUnionCommonFieldsAndRecursiveTrees(t *testing.T) {
	source := "package contract\ntype Protocol struct { Type string `json:\"type\"`; CredentialRef string `json:\"credentialRef,omitempty\"`; HTTP *HTTP `json:\"http,omitzero\"`; Socks5 *Socks5 `json:\"socks5,omitzero\"` }\ntype MatchTrace struct { Type string `json:\"type\"`; State string `json:\"state\"`; Children []MatchTrace `json:\"children,omitempty\"` }"
	file, err := parser.ParseFile(token.NewFileSet(), "contract.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, decl := range file.Decls {
		for _, spec := range decl.(*ast.GenDecl).Specs {
			if err := writeType(&out, spec.(*ast.TypeSpec), ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	result := out.String()
	if !strings.Contains(result, `type: "http"; credentialRef?: string; http: HTTP`) || !strings.Contains(result, `type: "socks5"; credentialRef?: string; socks5: Socks5`) {
		t.Fatalf("lost common field:\n%s", result)
	}
	if !strings.Contains(result, "export interface MatchTrace") || !strings.Contains(result, "children?: MatchTrace[]") {
		t.Fatalf("tree was treated as a tagged union:\n%s", result)
	}
}
