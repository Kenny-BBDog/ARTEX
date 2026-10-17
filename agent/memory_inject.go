package agent

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/memory"
)

// The cross-task experience layer ("shared brain"): a directory-backed store where
// finished tasks' observed conclusions land (server/lessons.go) and every agent
// facing a target reads from. Two delivery modes, chosen per lesson:
//
//   - PULL (RecallMemory tool): always available — for the mid-run "wait, has
//     anything seen this before?" lookup.
//   - PUSH: hand-picked entries written into the prompt at run start. Push is the
//     delivery that matters (probed on run 5: a listed-but-unpushed tool never gets
//     invoked), but WHO gets which lesson is structural, not similarity: run 7
//     measured why.
//
// What run 7 measured. AutoInject scores the whole prompt text; for a worker that
// text is the situational overview, which mentions the target constantly. Every
// entry carrying the same target therefore scores similar, and the worker got the
// same handful of target-scoped lessons regardless of what its intent was about —
// lessons about JWT while probing uploads, lessons about NoSQL while probing XSS.
// Two pathologies followed: it re-chewed already-confirmed directions (the depth
// drop: 24 findings on 13 routes vs run 6's 37 on ~17), and it never saw the one
// lesson that pointed OUT of a hole. Recall fell 34→23 while every downstream
// signal (confirmed ratio, premature_exhaustion) stayed clean: the routes were
// real, there were just the wrong ones.
//
// So push is by intent: the caller scores the store against the ONE thing the
// run is for — the intent summary for workers, the situational snapshot for
// planners — and writes the picks into the input explicitly (injectLessons).
// Structure over similarity: an intent mentioning "upload" must get upload
// lessons, and must NOT get a wall of same-target everything.

const lessonMaxChars = 2400 // hard cap on the injected block itself

// pickLessons scores the store against a query and caps aggressively. Shared by
// worker and planner push paths so both hands behave the same.
//
// The threshold is RELATIVE (≥ top/2), not absolute. Measured with an absolute
// bar: an upload intent scored its upload lesson 2 (only "file"/"up" fragments
// hit the body; the description's "XXE/ZipSlip" gluedcompound misses "upload"),
// while a NoSQL intent scored 6 — one absolute bar either starves the first or
// floods with the second. Relative to the query's own top hit, 2 ≥ 2/2 keeps the
// real one; same-top noise (http/local background hits scoring 1-2 against a
// top of 6+) still falls out.
func pickLessons(store *memory.Store, query string) []memory.Memory {
	if strings.TrimSpace(query) == "" {
		return nil
	}
	hits := store.Relevant(query, 4)
	if len(hits) == 0 {
		return nil
	}
	top := scoredRelevance(hits[0], query)
	if top < 2 { // <2 意味着名/描述/内容全部只有碎片级重合——整场是背景噪声，不是经验传递
		return nil
	}
	picked := hits[:0]
	for _, m := range hits {
		if scoredRelevance(m, query)*2 >= top {
			picked = append(picked, m)
		}
	}
	return picked
}

// scoredRelevance mirrors memory.score()'s weighting for the kept-or-dropped
// decision. name 3 × desc 2 × body 1 — the same arithmetic, so the two layers
// agree on what "relevant" means. Tokenizer is our own copy of memory.tokenize
// (unexported there): [a-z0-9_]+ minus English stopwords, so filters agree too.
func scoredRelevance(m memory.Memory, query string) int {
	matched := 0
	for _, t := range memoryTokens(query) {
		if strings.Contains(m.Name, t) {
			matched += 3
		}
		if strings.Contains(m.Description, t) {
			matched += 2
		}
		if strings.Contains(m.Content, t) {
			matched++
		}
	}
	return matched
}

// memoryTokens mirrors norma/memory's tokenize (relevant.go:8-18): [a-z0-9_]+,
// len≥2, English stopwords out. Kept in lockstep so filter and scorer see the
// same tokens; a divergence here would silently re-open the noise-token hole.
func memoryTokens(s string) []string {
	var re = regexp.MustCompile(`[a-z0-9_]+`)
	var stop = map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true, "of": true,
		"to": true, "in": true, "is": true, "it": true, "for": true, "on": true,
		"do": true, "i": true, "you": true, "my": true, "me": true, "what": true,
		"how": true, "can": true, "with": true, "this": true, "that": true,
	}
	var out []string
	for _, w := range re.FindAllString(strings.ToLower(s), -1) {
		if len(w) >= 2 && !stop[w] {
			out = append(out, w)
		}
	}
	return out
}

// memoryInject configures the SDK-side memory surface: the RecallMemory /
// RecordMemory tools (pull + write), with AutoInject OFF — push delivery is
// caller-owned (injectLessons) precisely because scoring belongs to the run's
// structural context, not to the whole prompt blob. See the measured rationale
// in the file header.
func memoryInject(workDir string) *agentcore.MemoryOptions {
	return &agentcore.MemoryOptions{
		Store:                memory.NewStore(memoryPath(workDir)),
		AutoInject:           false, // push by intent, not by prompt similarity
		MaxInject:            3,
		IncludeIndexInPrompt: false,
	}
}

func memoryPath(workDir string) string { return filepath.Join(workDir, "memory") }

// injectLessons renders the per-intent push block, or "" when nothing matches.
// The block is written as standing guidance, reads as past observations (they
// literally are), and says what to DO with each: reuse, or re-test with the
// reason the entry gives. It never asserts "this is done for you".
func injectLessons(store *memory.Store, query string) string {
	picked := pickLessons(store, query)
	if len(picked) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【跨任务经验（此前另一个任务在同一目标上的实测观察，只复述结论不重复劳动）】\n")
	b.WriteString("逐条看：与本意图【相关】的，按经验避开已证死路、或直接复用已证的可用路径；与本意图【无关】的忽略即可——那条经验不是给你的。\n\n")
	for _, m := range picked {
		b.WriteString("--- " + m.Name + " ---\n")
		b.WriteString(strings.TrimSpace(m.Content))
		b.WriteString("\n\n")
	}
	out := b.String()
	if len([]rune(out)) > lessonMaxChars {
		out = string([]rune(out)[:lessonMaxChars]) + "…\n（超限截断；其余可用 RecallMemory 按需查回）"
	}
	return out
}

// intentLessonQuery is the query surface for a worker's push: the intent's own
// summary text. The scorer weights this against names/descriptions with the
// SAME tokenizer the write side coined, so what matters travels.
func intentLessonQuery(intent *db.Node) string {
	if intent == nil {
		return ""
	}
	var p map[string]any
	if json.Unmarshal(intent.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok {
			return s
		}
	}
	return "" // fallback: no summary → no push (never push on payload dump)
}
