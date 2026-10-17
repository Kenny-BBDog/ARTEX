package agent

import (
	actool "github.com/Autumn-27/norma/tool"
)

// OpenCode's gateway refuses (403 FreeTierError) any request whose tools array
// lacks a tool named EXACTLY "read" — the capitalised "Read" ARTEX ships does not
// satisfy it, and the check ignores the description and schema. Both entry points
// that talk to a provider need the alias, which is why it lives here rather than
// in the server layer:
//
//   - real agent runs, via server/assembly.go's ToolAugment
//   - the connection test (TestConnection), which builds its own tool list and
//     would otherwise 403 where a real run succeeds
type opencodeReadAliasTool struct{ actool.CoreTool }

func (opencodeReadAliasTool) Name() string { return "read" }

// OpencodeReadAlias is ARTEX's Read tool under the lowercase name OpenCode
// insists on. Registry.Schemas() renders every tool through Name() and calls are
// dispatched by the same name, so wrapping Read and overriding only Name() is
// enough: the model sees Read's own description and schema, and Call runs Read's
// own implementation.
func OpencodeReadAlias() actool.CoreTool { return opencodeReadAliasTool{actool.NewRead()} }

// OpenCodeReadToolName is the exact tool name the gateway looks for. Kept as a
// constant so the server layer's dedup (a caller that already defines "read")
// can't drift from the alias's own name.
const OpenCodeReadToolName = "read"
