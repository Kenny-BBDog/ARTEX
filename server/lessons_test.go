package server

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/memory"
)

func testSched(t *testing.T) *Scheduler {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return &Scheduler{pg: pg}
}

// readLessonNames lists the memory entry names in dataDir/memory through the same
// store implementation the delivery side reads — write and delivery must agree.
func readLessonNames(dataDir string) ([]string, error) {
	mems, err := memory.NewStore(memoryDirPath(dataDir)).Scan()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(mems))
	for _, m := range mems {
		out = append(out, m.Name)
	}
	return out, nil
}

func newLessonStore(dataDir string) *memory.Store {
	return memory.NewStore(memoryDirPath(dataDir))
}

// TestDeriveLessonsWritesOnlyObservedConclusions pins the write filter: observed
// facts in, inferences and wrap-up records out. The shared brain must never steer
// future tasks with a guess — that is the verifier's gate, not the sweep's.
func TestDeriveLessonsWritesOnlyObservedConclusions(t *testing.T) {
	sc := testSched(t)
	dataDir := t.TempDir()
	task, err := sc.pg.CreateTask("lessons: observed-only filter", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.pg.DeleteTask(task.ID) })
	exp := sc.pg.Exploration(task.ExplorationID)

	intent, err := exp.AddNode(db.KindIntent, map[string]any{"summary": "探"}, 0, "done", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(conf, summary string, wrapup bool) {
		t.Helper()
		p := map[string]any{"summary": summary, "confidence": conf}
		if wrapup {
			p["wrapup"] = true
		}
		id, err := exp.AddNode(db.KindFact, p, 5, "confirmed", "work#1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := exp.Link(intent, db.RelYields, id); err != nil {
			t.Fatal(err)
		}
	}
	mk("observed", "本部署不存在 GraphQL 接口：/graphql 与 /api/graphql 均 404", false)
	mk("observed", "JWT 接受 alg:none 未签名令牌并认证成功", false)
	mk("inferred", "看起来对象存储可能配置开放", false)
	mk("observed", "任务超时收尾：没来得及写回", true)

	sc.deriveLessons(task.ID, dataDir)

	entries, err := readLessonNames(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected exactly the 2 observed facts as lessons, got %d: %v", len(entries), entries)
	}
	for _, n := range entries {
		if !strings.HasPrefix(n, fmt.Sprintf("obs-t%d-f", task.ID)) {
			t.Errorf("unexpected lesson name %q", n)
		}
	}

	// Re-run the same task: idempotence — no duplicates, no error. This mirrors
	// what a server restart does to the outcome sweep (TasksNeedingOutcome can
	// re-deliver a task).
	sc.deriveLessons(task.ID, dataDir)
	again, err := readLessonNames(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 2 {
		t.Errorf("re-running deriveLessons produced duplicates: %d entries", len(again))
	}
}

// TestLessonContentQuotesTheObservation checks the rendered entry carries the
// specifics (summary + evidence + source) — the whole point of injecting past
// observations instead of abstractions — including the target label, so the
// relevance scorer can match a future task mentioning the same target.
// CreateTask(description, goal, …): the FIRST arg is the description, which is
// where the target lives (db create handler builds it as "对 {goal} 的评估").
func TestLessonContentQuotesTheObservation(t *testing.T) {
	sc := testSched(t)
	dataDir := t.TempDir()
	task, err := sc.pg.CreateTask("对 http://js.local 的连续渗透（quote check）", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.pg.DeleteTask(task.ID) })
	exp := sc.pg.Exploration(task.ExplorationID)
	intent, err := exp.AddNode(db.KindIntent, map[string]any{"summary": "JWT 测试"}, 0, "done", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := exp.AddNode(db.KindFact, map[string]any{
		"summary":    "JWT 接受 alg:none",
		"evidence":   "curl -H 'Authorization: Bearer AAAA.BBBB.' /api/Users/1 → 200 admin",
		"confidence": "observed",
	}, 5, "confirmed", "work#1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.Link(intent, db.RelYields, fid); err != nil {
		t.Fatal(err)
	}

	sc.deriveLessons(task.ID, dataDir)

	mems, err := newLessonStore(dataDir).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(mems) != 1 {
		t.Fatalf("want 1 lesson, got %d", len(mems))
	}
	m := mems[0]
	all := m.Content + "\n" + m.Description
	for _, want := range []string{"alg:none", "AAAA.BBBB", "任务 #", "observed"} {
		if !strings.Contains(all, want) {
			t.Errorf("lesson missing %q in:\nname=%q\ndesc=%q\ncontent=%s", want, m.Name, m.Description, m.Content)
		}
	}
	if !strings.Contains(all, "js.local") {
		t.Errorf("lesson does not name its target anywhere — future tasks on this target can't match it:\n%s", all)
	}
}

// TestLessonDeliveryMatchesWriteStore is the invariant that makes a lesson
// reachable: the ordering-affecting metadata the write side sets (type) must be
// one the delivery side reads for relevance scoring.
func TestLessonDeliveryMatchesWriteStore(t *testing.T) {
	sc := testSched(t)
	dataDir := t.TempDir()
	task, err := sc.pg.CreateTask("delivery parity", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.pg.DeleteTask(task.ID) })
	exp := sc.pg.Exploration(task.ExplorationID)
	intent, err := exp.AddNode(db.KindIntent, map[string]any{"summary": "x"}, 0, "done", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := exp.AddNode(db.KindFact, map[string]any{
		"summary":    "POST /file-upload 拒绝 .js 与 zip 双扩展", "detail": "全部 403",
		"confidence": "observed",
	}, 5, "confirmed", "work#1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.Link(intent, db.RelYields, fid); err != nil {
		t.Fatal(err)
	}

	sc.deriveLessons(task.ID, dataDir)

	// Delivery: a future prompt mentioning the same surface must hit the entry.
	relevant := newLessonStore(dataDir).Relevant("file-upload extension restrictions on this target", 3)
	if len(relevant) != 1 {
		t.Fatalf("Relevant() found %d entries for a matching prompt, want 1 (write store and delivery store must share tokenization)", len(relevant))
	}
	// An unrelated prompt must not.
	if got := newLessonStore(dataDir).Relevant("windows domain controller kerberos", 3); len(got) != 0 {
		t.Errorf("unrelated prompt matched %d entries: %+v", len(got), got)
	}
	_ = context.Background
}

// TestLessonEntryNamesSurviveSlug pins why the name scheme must be ASCII:
// norma/memory slugs entry names through [^a-z0-9]+ (memory.go slugRe), so a
// Chinese name would slug to an empty string and silently fail to persist.
func TestLessonEntryNamesSurviveSlug(t *testing.T) {
	name := lessonName(7, 12)
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		t.Fatalf("lessonName produced %q which norma/memory would slug away", name)
	}
	// And the directory the write side uses is the one memoryInject reads.
	if want := filepath.Join("data", "memory"); memoryDirPath("data") != want {
		t.Fatalf("memoryDirPath = %q, want %q (agent/memory_inject.go must agree)", memoryDirPath("data"), want)
	}
}
