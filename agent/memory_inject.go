package agent

import (
	"path/filepath"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/memory"
)

// memoryInject configures the cross-task experience layer on an agent run: a
// directory-backed memory store whose entries are force-injected (AutoInject)
// before each prompt — the "shared brain" lesson delivery. Every agent that
// faces the target (worker / planner / main agent) shares one directory, so a
// conclusion any of them reached in a past task reaches all of them here.
//
// Why forced injection and not a pull tool: measured (run-5 probe), the Skill
// meta-tool was delivered to the worker with the listing embedded in its
// description and the worker never invoked it — PULL depends on the model
// deciding to look, which is exactly the step that failed. AutoInject appends
// the ≤MaxInject most relevant entries to the user turn inside agentcore
// (agentcore.Prompt, agentcore.go:435-444), which no model behavior can skip.
//
// Nil results (empty dir, no relevant hits) are nil options — agents run
// unchanged until the store has content worth sharing.
func memoryInject(workDir string) *agentcore.MemoryOptions {
	store := memory.NewStore(memoryPath(workDir))
	// Index-in-system-prompt stays off: the system prompt is cached/stable per
	// round by design (planner.go move-out comment), and the index would inject
	// a mutable global artifact into it. AutoInject rides the user turn instead.
	return &agentcore.MemoryOptions{
		Store:                store,
		AutoInject:           true,
		MaxInject:            3,
		IncludeIndexInPrompt: false,
	}
}

func memoryPath(workDir string) string { return filepath.Join(workDir, "memory") }
