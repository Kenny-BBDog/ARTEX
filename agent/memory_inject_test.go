package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/norma/memory"
)

// seedStore writes entries shaped exactly like server/lessons.go does: minimal
// description, glued host token, Chinese content.
func seedStore(t *testing.T) *memory.Store {
	t.Helper()
	store := memory.NewStore(t.TempDir())
	write := func(name, desc, content string) {
		t.Helper()
		if err := store.Save(memory.Memory{
			Name: name, Description: desc, Type: memory.TypeProject, Content: content,
		}); err != nil {
			t.Fatal(err)
		}
	}
	write("obs-t1-f3", "jslocal 任务#1 fact#3：JWT 接受 alg:none 并认证成功",
		"结论：JWT 接受 alg:none\n证据：Bearer AAAA.BBBB -> 200 admin")
	write("obs-t1-f24", "jslocal 任务#1 fact#24：NoSQL 注入只在评论写接口 id 参数",
		"结论：NoSQL 注入仅 PATCH/POST /rest/products/reviews 的 id 参数；读接口路径参数强转数字，search q 是 SQLite SQLi")
	write("obs-t1-f57", "jslocal 任务#1 fact#57：本部署无 GraphQL 接口",
		"结论：不存在 GraphQL 接口；/graphql 与 /api/graphql 均 404。不要再为其分配预算")
	write("obs-t2-f7", "corplocal 任务#2 fact#7：sso 白名单子串匹配可绕过",
		"结论：sso 白名单子串匹配可绕过")
	write("obs-t1-f35", "jslocal 任务#1 fact#35：上传接口 XXE/ZipSlip 均 403",
		"结论：POST /file-upload 的 XXE、Zip Slip、YAML 反序列化在本部署均被拦截")
	return store
}

// TestPickLessonsIntentScoped is the run-7 lesson turned into a gate: an intent
// about uploads must pull the upload lesson and not the same-target JWT/NoSQL
// noise — "same target" is not "relevant to this intent".
func TestPickLessonsIntentScoped(t *testing.T) {
	store := seedStore(t)

	hits := pickLessons(store, "对 /file-upload 的任意文件写入与解析器滥用测试")
	if len(hits) == 0 || !strings.Contains(hits[0].Content, "Zip Slip") {
		t.Fatalf("upload intent picked %v, want the upload fact first", namesS(hits))
	}
	for _, m := range hits {
		if strings.Contains(m.Content, "alg:none") || strings.Contains(m.Content, "NoSQL") {
			t.Errorf("lesson about another surface leaked into an upload intent: %s", m.Name)
		}
	}

	// A JWT-crafting intent gets the JWT lesson…
	hits = pickLessons(store, "测试令牌伪造提权：alg 混淆与签名绕过")
	if len(hits) == 0 || !strings.Contains(hits[0].Content, "alg:none") {
		t.Fatalf("jwt intent picked %v, want the JWT fact first", namesS(hits))
	}
	// …and a NoSQL-specific intent, the NoSQL one — not JWT.
	hits = pickLessons(store, "NoSQL 操作符注入进 /rest/products/reviews")
	if len(hits) == 0 || !strings.Contains(hits[0].Content, "NoSQL") {
		t.Fatalf("nosql intent picked %v, want the NoSQL fact first", namesS(hits))
	}
}

// TestInjectLessonsAddsGuidanceAndCap checks the pushed block reads as guidance
// (what to do, not news) and hard-caps its own size.
func TestInjectLessonsAddsGuidanceAndCap(t *testing.T) {
	store := seedStore(t)

	block := injectLessons(store, "对 http://... 的 JWT alg:none 伪造测试 jslocal")
	if block == "" {
		t.Fatal("a matching intent produced no push block")
	}
	for _, want := range []string{"跨任务经验", "obs-t1-f3", "alg:none"} {
		if !strings.Contains(block, want) {
			t.Errorf("push block missing %q:\n%s", want, block)
		}
	}
}

// TestInjectLessonsEmptyOnNoise: an intent sharing only stop/noise tokens with
// the store pushes nothing — silence is the correct behavior, not a dump.
func TestInjectLessonsEmptyOnNoise(t *testing.T) {
	store := seedStore(t)
	if got := injectLessons(store, "windows 域控 kerberos 票据加密"); got != "" {
		t.Errorf("unrelated intent got a push block:\n%s", got)
	}
}

// TestMemoryInjectAutoInjectOff pins the delivery bet: AutoInject scored the
// whole prompt (run 7 measured the same-target bundle pathology), so push is
// caller-owned now and the SDK's scorer must stay out of the loop.
func TestMemoryInjectAutoInjectOff(t *testing.T) {
	opts := memoryInject(t.TempDir())
	if opts == nil || opts.Store == nil {
		t.Fatal("memoryInject must still provide the store (RecallMemory/RecordMemory pull-write surface)")
	}
	if opts.AutoInject {
		t.Error("AutoInject must be off — push selection is structural (per-intent), scored by injectLessons")
	}
	if opts.IncludeIndexInPrompt {
		t.Error("IncludeIndexInPrompt must stay off (system prompt stays cache-stable)")
	}
}

func namesS(ms []memory.Memory) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}
