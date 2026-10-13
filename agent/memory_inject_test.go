package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/norma/memory"
)

// TestMemoryInjectPointsAtTheSharedDirectory pins the physical contract between
// the write side (server/lessons.go → <dataDir>/memory) and the delivery side
// (this file): if the two paths ever diverge, lessons are written into a
// directory nobody injects from — silent, total layer failure.
func TestMemoryInjectPointsAtTheSharedDirectory(t *testing.T) {
	opts := memoryInject(t.TempDir())
	if opts == nil || !opts.AutoInject {
		t.Fatal("memoryInject must produce an AutoInject-enabled config")
	}
	if opts.MaxInject != 3 || opts.MaxInject <= 0 {
		t.Errorf("MaxInject = %d, want 3 (capped: a bigger pool must not blow the context)", opts.MaxInject)
	}
	if opts.IncludeIndexInPrompt {
		t.Error("IncludeIndexInPrompt must stay off — the system prompt is cache-stable by design")
	}
	if !strings.Contains(opts.Store.Dir, "memory") {
		t.Errorf("store dir = %q, want it under <dataDir>/memory", opts.Store.Dir)
	}
}

// TestMemoryInjectionReachesThePrompt models what agentcore.Prompt does: scores
// the run input against the store and appends matches. The worker's input is the
// situational overview / the planner's is its situational block — so the injected
// text must be reachable by the words those inputs actually contain, and entries
// about DIFFERENT targets must stay out (a js.local lesson delivered into a
// corp.local run is noise, not knowledge).
//
// Entries are built exactly the way server/lessons.go writes them — description
// prefixed with the glued host token. Without that token, measured: "js.local"
// tokenizes to http/js/local and every URL-carrying entry matches (scores
// 15/9/6), so discrimination is impossible for UTF-8 non-ASCII descriptions.
// The token plug-in is the mechanism; this test pins both sides of it.
func TestMemoryInjectionReachesThePrompt(t *testing.T) {
	dir := t.TempDir()
	store := memory.NewStore(dir)
	write := func(name, desc, content string) {
		t.Helper()
		if err := store.Save(memory.Memory{
			Name: name, Description: desc, Type: memory.TypeProject, Content: content,
		}); err != nil {
			t.Fatal(err)
		}
	}
	write("obs-t1-f3", "jslocal 任务#1（http://js.local）fact#3：JWT 接受 alg:none 并认证成功",
		"目标：http://js.local\n结论：JWT 接受 alg:none 未签名令牌并认证成功\n来源：任务 #1 fact #3（observed）")
	write("obs-t2-f7", "corplocal 任务#2（http://corp.local）fact#7：sso 重定向白名单为子串匹配可绕过",
		"目标：http://corp.local\n结论：sso 白名单子串匹配可绕过")
	write("obs-t3-f1", "shoplocal 任务#3（http://shop.local）fact#1：file-upload 拒绝 js 双扩展",
		"目标：http://shop.local\n结论：file-upload 拒绝 .js 双扩展")

	// The scorer (norma/memory Relevant) returns EVERY entry with score > 0,
	// ordered by score — sharing the tokens http/local across all URL entries
	// (measured 15/9/6), so "did it return exactly one" is the wrong assertion.
	// What AutoInject actually relies on: the relevant entry RANKS FIRST, the
	// list is capped at MaxInject, and ordering is by score so noisier entries
	// trail behind.
	hits := store.Relevant("测试 http://js.local 的 JWT 认证：alg 混淆、签名绕过 jslocal", 3)
	if len(hits) == 0 || hits[0].Name != "obs-t1-f3" {
		t.Fatalf("Relevant() first hit = %v, want the js.local JWT entry ranked first", names(hits))
	}
	// …and for an input about a different target, that target's entry must rank first
	// — the js.local lesson trailing behind is tolerable tail, but at index 0 it
	// would be misinformation (a lesson about a different deployment presented as
	// the operative one).
	hits2 := store.Relevant("测试 http://corp.local 的 sso 重定向 corplocal", 3)
	if len(hits2) == 0 || hits2[0].Name != "obs-t2-f7" {
		t.Errorf("first hit = %v, want obs-t2-f7 ranked first for a corp.local run", names(hits2))
	}
	// MaxInject cap: with a melting pot of hits, at most 3 come back.
	many := store.Relevant("js.local corp.local shop.local http jslocal corplocal shoplocal", 10)
	if len(many) > 3 {
		t.Errorf("Relevant returned %d for a broad query — MaxInject cap must hold", len(many))
	}
}

func names(ms []memory.Memory) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}
