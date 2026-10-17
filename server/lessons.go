package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/memory"
)

// hostTokenRe overlaps norma/memory's own tokenizer ([a-z0-9_]+): a word has to
// exist in THAT token space to score anything, so the discriminator is built
// from the same alphabet.
var hostTokenRe = regexp.MustCompile(`[a-z0-9]+(\.[a-z0-9]+)+`)

// lessons.go — the write side of the cross-task experience layer ("shared brain").
//
// When a task reaches a terminal state the outcome sweep already recomputes its
// summary (server/scheduler.go refreshOutcomes). This file rides the same sweep and
// distills the task's CONFIRMED observations into the shared memory directory that
// every worker / planner / main agent is force-fed from (agent/memory_inject.go).
//
// What gets in is deliberate: only facts stamped confidence='observed' — an
// observation the worker actually saw (this deployment has no GraphQL endpoint;
// the JWT accepts alg:none; uploads reject .js) — NOT its inferences ("seems
// injectable", "might be vulnerable"). Inferences need the verifier's independent
// voice before they may steer future tasks; observations do not, because they
// record what HAPPENED, not what it means. Auto-promoting observations costs
// nothing and cannot poison the pool with guesses.
//
// Storage is the filesystem (norma/memory format), not a table: the pool is
// global, hand-editable, hand-deletable — the user opens <dataDir>/memory/ and
// prunes it. A rejected lesson is a deleted file.

const (
	// lessonBodyCap bounds the per-entry body: an entry that reads like the whole
	// fact table wastes the injection budget (AutoInject appends the full text).
	lessonBodyCap = 1200
	// lessonScanLimit bounds the fact scan per task; a huge task's older facts are
	// folded into cold digests anyway.
	lessonScanLimit = 200
)

// deriveLessons distills one finished task's observed facts into the shared memory
// store. Called from the scheduler right after the outcome UPSERT for that task.
func (sc *Scheduler) deriveLessons(taskID int64, dataDir string) {
	task, err := sc.pg.GetTask(taskID)
	if err != nil || task == nil {
		return
	}
	exp := sc.pg.Exploration(task.ExplorationID)
	facts, err := exp.ListByKind(db.KindFact, lessonScanLimit)
	if err != nil {
		log.Printf("[lessons] 读事实 task=%d: %v", taskID, err)
		return
	}

	store := memory.NewStore(memoryDirPath(dataDir))
	existing, err := store.Scan()
	if err != nil {
		log.Printf("[lessons] 读经验库失败 task=%d: %v", taskID, err)
		return
	}
	known := make(map[string]bool, len(existing))
	for _, m := range existing {
		known[m.Name] = true
	}

	target := clip(task.Description, 60) // 任务描述点名了目标，人就是按它匹配经验的
	// hostToken: the scorer (norma/memory tokenize) splits on [a-z0-9_]+ only, so
	// "http://js.local" contributes the trio http/js/local that EVERY entry carrying
	// a URL matches (measured: three entries, scores 15/9/6, zero discrimination).
	// Gluing the host to a single token (js.local → jslocal; 127.0.0.1 → 001 in
	// practice; eng corpus keeps [-a-z0-9]) gives the future run's input a token
	// only this entry owns — discrimination lives here, not in hope.
	hostToken := hostSlug(task.Description)

	added := 0
	for _, f := range facts {
		if f.Kind != db.KindFact || f.State == "deleted" {
			continue
		}
		var p map[string]any
		if err := json.Unmarshal(f.Payload, &p); err != nil {
			continue
		}
		if p["confidence"] != "observed" {
			continue // 猜想不入库 —— 见文件头
		}
		if b, ok := p["wrapup"].(bool); ok && b {
			continue // 收尾事实是「这次 run 怎么结束的」，不是对目标的观察
		}
		summary := strings.TrimSpace(anyStr(p["summary"]))
		if summary == "" {
			continue
		}
		name := lessonName(hostToken, summary)
		if known[name] {
			continue // 同目标同结论已入库：内容寻址天然幂等（重放 sweep / 跨任务重复结论都跳过）
		}
		if err := store.Save(memory.Memory{
			Name: name,
			Description: fmt.Sprintf("%s 任务#%d（%s）fact#%d：%s",
				hostToken, taskID, clip(target, 40), f.ID, clip(summary, 100)),
			Type:    memory.TypeProject,
			Content: renderLesson(target, taskID, f.ID, p),
		}); err != nil {
			log.Printf("[lessons] 写入失败 task=%d fact=%d: %v", taskID, f.ID, err)
			continue
		}
		added++
	}
	if added > 0 {
		log.Printf("[lessons] 任务#%d 提炼 %d 条经验入库（同名跳过=幂等）", taskID, added)
	}
}

// renderLesson formats one observed fact, quoting what the worker actually saw
// (its summary + evidence line) rather than a summary-of-a-summary — the value of
// an observation is in the specifics.
func renderLesson(target string, taskID, factID int64, p map[string]any) string {
	var b strings.Builder
	b.WriteString("目标：" + target + "\n")
	b.WriteString("结论：" + clip(anyStr(p["summary"]), 200) + "\n")
	if ev := strings.TrimSpace(anyStr(p["evidence"])); ev != "" {
		b.WriteString("证据：" + clip(ev, 300) + "\n")
	}
	if det := strings.TrimSpace(anyStr(p["detail"])); det != "" {
		b.WriteString("细节：" + clip(det, 700) + "\n")
	}
	fmt.Fprintf(&b, "\n来源：任务 #%d fact #%d（observed：本次运行实际看到的记录）。\n", taskID, factID)
	b.WriteString("适用时机：面对同样技术栈/路径的目标时，先想这条，再决定是否重新探测。")
	out := b.String()
	out = strings.ReplaceAll(out, "\r\n", "\n")
	if utf8.RuneCountInString(out) > lessonBodyCap {
		out = string([]rune(out)[:lessonBodyCap]) + "…"
	}
	return out
}

// lessonName is content-addressed: target + the conclusion statement, hashed.
//
// Two properties, both measured-for. Deterministic: re-running the sweep on the
// same task, or reaching the same conclusion in a later task, resolves to the
// same name and dedupes — the library holds conclusions, not mentions.
// Collision-proof: the first cut keyed on task id + fact id, which silently
// dropped run-8's conclusions because our e2e harness resets the DB per run and
// every task is id 1 — run 8's fact #24 was "already present" as run 7's. Task
// ids are unique in production so the bug hid there, but keying identity on
// provenance rather than on the claim is wrong in both worlds.
//
// ASCII by contract: norma/memory slugs names through [^a-z0-9] (- and _ survive
// as separators), so a Chinese name would slug to empty and never persist.
func lessonName(hostToken, summary string) string {
	key := strings.ToLower(strings.TrimSpace(hostToken) + "|" + strings.Join(lessonTokens(summary), " "))
	sum := sha256.Sum256([]byte(key))
	return "obs-" + hex.EncodeToString(sum[:])[:12]
}

// lessonTokens normalises a conclusion into comparable tokens for the name key.
// Kept: ASCII [a-z0-9_] and CJK ideographs (unicode.Han) — the latter so two
// Chinese summaries differing only in punctuation hash alike. Dropped: everything
// else, including CJK punctuation, which is NOT Han ("接口，" must equal "接口").
func lessonTokens(s string) []string {
	return strings.Fields(strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', unicode.Is(unicode.Han, r):
			return r
		default:
			return ' '
		}
	}, strings.ToLower(s)))
}

// hostSlug glues the first host-ish token of the task description into one ASCII
// word (js.local → jslocal, 127.0.0.1 → 127local... actually 001). Empty when the
// description has no host-looking token — the description line then just lacks a
// discrimination term, which degrades to today's behavior, never breaks.
func hostSlug(desc string) string {
	tokens := hostTokenRe.FindAllString(strings.ToLower(desc), 2)
	if len(tokens) == 0 {
		return ""
	}
	glued := strings.ReplaceAll(tokens[0], ".", "")
	if glued == "http" || glued == "https" { // 描述以 URL 开头时取 host 段而非 scheme
		if len(tokens) > 1 {
			glued = strings.ReplaceAll(tokens[1], ".", "")
		} else {
			return ""
		}
	}
	return glued
}

// memoryDirPath mirrors agent.memoryInject's path; one directory, two surfaces.
func memoryDirPath(dataDir string) string {
	return filepath.Join(dataDir, "memory")
}

func clip(s string, max int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}

func anyStr(v any) string {
	s, _ := v.(string)
	return s
}
