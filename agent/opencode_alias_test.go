package agent

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// The OpenCode free tier needs a tool whose name is EXACTLY "read" — the
// capitalised "Read" ARTEX ships does not satisfy it, and the gateway checks the
// name while ignoring description and schema. These tests pin the rendering that
// actually reaches the wire.
func TestOpencodeReadAliasRendersAsLowercaseRead(t *testing.T) {
	alias := OpencodeReadAlias()
	if got := alias.Name(); got != OpenCodeReadToolName {
		t.Fatalf("alias Name() = %q, want exactly %q", got, OpenCodeReadToolName)
	}
	if OpenCodeReadToolName != "read" {
		t.Fatalf("OpenCodeReadToolName = %q, want %q", OpenCodeReadToolName, "read")
	}
}

func TestOpencodeReadAliasKeepsReadBehaviour(t *testing.T) {
	// The alias must be a working tool, not a name-only stub: the model can and
	// will call it, and it should read a file exactly like Read does.
	read := actool.NewRead()
	alias := OpencodeReadAlias()

	if got, want := alias.Description(), read.Description(); got != want {
		t.Errorf("alias Description() differs from Read's:\n got %q\nwant %q", got, want)
	}
	aliasSchema, readSchema := alias.InputSchema(), read.InputSchema()
	if len(aliasSchema) == 0 {
		t.Fatal("alias InputSchema() is empty; it should carry Read's")
	}
	props, _ := aliasSchema["properties"].(map[string]any)
	if _, ok := props["file_path"]; !ok {
		t.Errorf("alias InputSchema() lost Read's file_path property: %v", aliasSchema)
	}
	if len(aliasSchema) != len(readSchema) {
		t.Errorf("alias InputSchema() has %d keys, Read's has %d", len(aliasSchema), len(readSchema))
	}
}

// Registry.Schemas() is what the harness hands the provider, so assert the alias
// survives rendering under its lowercase name alongside Read.
func TestOpencodeReadAliasSurvivesRegistryRendering(t *testing.T) {
	reg := actool.NewRegistry(actool.NewRead(), OpencodeReadAlias())
	names := map[string]bool{}
	for _, s := range reg.Schemas() {
		names[s.Name] = true
	}
	if !names["read"] {
		t.Fatalf("lowercase %q missing from rendered schemas: %v", OpenCodeReadToolName, names)
	}
	if !names["Read"] {
		t.Fatalf("Read missing from rendered schemas: %v", names)
	}
}
