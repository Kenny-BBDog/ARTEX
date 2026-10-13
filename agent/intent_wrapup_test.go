package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/harness"

	"github.com/Autumn-27/artex/db"
)

// wrapupFixture builds a task holding exactly one intent, in the given terminal state,
// with nothing yielded. The intent is never worked (0 tool calls) so it also sits in
// TaskDepth's thin-route population — the case where a mislabelled wrap-up fact would
// read as "the worker exhausted this route".
func wrapupFixture(t *testing.T, state string) (*db.DB, *db.ExplorationStore, *db.Node) {
	t.Helper()
	d := testDB(t)
	task, err := d.CreateTask("wrapup", "forced wrap-up fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	exp := d.Exploration(task.ExplorationID)
	id, err := exp.AddNode(db.KindIntent, map[string]any{"summary": "试一下注入"}, 0, state, "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := exp.GetNode(id)
	if err != nil || intent == nil {
		t.Fatalf("read intent: %+v err=%v", intent, err)
	}
	return d, exp, intent
}

// TestRunWrapupFactFilesAConclusionWhenTheRunLeftNone is the mechanism itself: a run
// that ended on its own without yielding anything gets one fact saying what it concluded.
//
// Measured on the Juice Shop run, the wrap-up prompt did its job — all three exhausted
// routes yielded facts and every terminal intent yielded something. That is exactly why
// this is a safety net and not a rule; what it exists for is the run where the model ends
// quietly and the intent is left carrying nothing, which the planner can only read as
// "unknown".
func TestRunWrapupFactFilesAConclusionWhenTheRunLeftNone(t *testing.T) {
	d, exp, intent := wrapupFixture(t, "done")

	const text = "试了 /rest/products/search 的 NoSQL 注入与几个绕过变体，没有回显；再往下得读源码，超出本次预算。"
	id, wrote := runWrapupFact(context.Background(), exp, intent, "work#1", harness.ReasonCompleted, text)
	if !wrote {
		t.Fatal("no wrap-up fact was filed for an intent that yielded nothing")
	}
	fact, err := exp.GetNode(id)
	if err != nil || fact == nil || fact.Kind != db.KindFact {
		t.Fatalf("wrap-up node: %+v err=%v", fact, err)
	}
	var p map[string]any
	if err := json.Unmarshal(fact.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if got, _ := p["summary"].(string); !strings.HasPrefix(got, wrapupFactPrefix) || !strings.Contains(got, "没有回显") {
		t.Errorf("summary = %q, want the worker's own conclusion, marked as a wrap-up", got)
	}
	if got, _ := p["detail"].(string); got != text {
		t.Errorf("detail = %q, want the run's full final text", got)
	}
	if w, _ := p["wrapup"].(bool); !w {
		t.Errorf("payload carries no wrapup flag: %+v", p)
	}

	// Trap 1: confidence. TaskDepth reads confidence='observed' as "the worker exhausted
	// the means"; a wrap-up is a statement about how the run ended, not an observation of
	// the target, so stamping it would make an untouched route look finished.
	if c, ok := p["confidence"]; ok {
		t.Errorf("wrap-up fact carries confidence=%v; it must carry none", c)
	}
	// Trap 2: asset anchors. UntouchedSurface counts an asset as worked on when it carries
	// a fact/finding anchor, and a wrap-up proves nobody worked on anything.
	var anchored int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1`, id).Scan(&anchored); err != nil {
		t.Fatal(err)
	}
	if anchored != 0 {
		t.Errorf("wrap-up fact anchored %d assets; UntouchedSurface would read those as worked on", anchored)
	}

	// The invariant the planner depends on: the intent now carries content.
	if n, err := exp.IntentYieldCount(intent.ID); err != nil || n != 1 {
		t.Fatalf("IntentYieldCount = %d err=%v, want 1", n, err)
	}

	// ...and the two traps actually stay shut, checked through the metrics that consume them.
	dp, err := exp.TaskDepth()
	if err != nil {
		t.Fatal(err)
	}
	if dp.RoutesThin != 1 {
		t.Fatalf("RoutesThin = %d, want 1 — the fixture must be in the thin population "+
			"or the premature-exhaustion check below proves nothing", dp.RoutesThin)
	}
	if dp.FactsObserved != 0 || dp.FactsInferred != 0 {
		t.Errorf("FactsObserved=%d FactsInferred=%d, want 0/0 — a wrap-up is not a confidence claim",
			dp.FactsObserved, dp.FactsInferred)
	}
	if dp.PrematureExhaustion != 0 {
		t.Errorf("PrematureExhaustion = %d, want 0 — the wrap-up fact must not read as "+
			"\"claimed exhaustion without spending anything\"", dp.PrematureExhaustion)
	}
}

// TestRunWrapupFactLeavesAYieldingIntentAlone is the reason this is affordable: on a run
// where the worker did write back — the normal case — it adds exactly nothing.
func TestRunWrapupFactLeavesAYieldingIntentAlone(t *testing.T) {
	d, exp, intent := wrapupFixture(t, "exhausted")

	fact, err := exp.AddNode(db.KindFact, map[string]any{"summary": "已确认：无回显", "confidence": "inferred"}, 5, "confirmed", "work#1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.Link(intent.ID, db.RelYields, fact); err != nil {
		t.Fatal(err)
	}

	before := countNodes(t, d, exp.ID())
	if _, wrote := runWrapupFact(context.Background(), exp, intent, "work#1", harness.ReasonMaxTurns, "时间到了"); wrote {
		t.Error("a second fact was filed for an intent that already yielded a conclusion")
	}
	if after := countNodes(t, d, exp.ID()); after != before {
		t.Errorf("node count went %d → %d, want unchanged", before, after)
	}
}

// countNodes is scoped to the exploration: the agent package's tests share one database,
// so an unscoped count would pick up another test's fixture.
func countNodes(t *testing.T, d *db.DB, expID int64) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, expID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRunWrapupFactSkipsCallerAbortedRuns: a pause, a planner kill or a shutdown is not a
// verdict on the route. The intent goes back to the frontier or is marked stopped, so
// writing "this route concluded X" onto it would assert an outcome that never happened.
func TestRunWrapupFactSkipsCallerAbortedRuns(t *testing.T) {
	_, exp, intent := wrapupFixture(t, "exhausted")

	for _, reason := range []harness.TerminalReason{harness.ReasonAbortedTools, harness.ReasonAbortedStreaming} {
		if id, wrote := runWrapupFact(context.Background(), exp, intent, "work#1", reason, "被打断前的一些想法"); wrote {
			t.Errorf("filed fact #%d for an externally aborted run (%s)", id, reason)
		}
	}

	// A context-cancelled cancel with no terminal event at all is the same situation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if id, wrote := runWrapupFact(ctx, exp, intent, "work#1", "", "被打断前的一些想法"); wrote {
		t.Errorf("filed fact #%d for a cancelled run with no terminal reason", id)
	}

	if n, err := exp.IntentYieldCount(intent.ID); err != nil || n != 0 {
		t.Fatalf("IntentYieldCount = %d err=%v, want 0", n, err)
	}
}

// TestRunWrapupFactRecordsHowAnEmptyRunEnded covers the run that ends with no text at all
// — a provider error, an empty stop, a blocked run. The point is the difference it makes
// to the planner: "this direction is untested" and "this direction is a dead end" demand
// opposite next moves, and before this they looked identical on the graph.
func TestRunWrapupFactRecordsHowAnEmptyRunEnded(t *testing.T) {
	_, exp, intent := wrapupFixture(t, "blocked")

	id, wrote := runWrapupFact(context.Background(), exp, intent, "work#1", harness.ReasonModelError, "")
	if !wrote {
		t.Fatal("a run that ended without text left the intent empty")
	}
	fact, err := exp.GetNode(id)
	if err != nil || fact == nil {
		t.Fatalf("wrap-up node: %+v err=%v", fact, err)
	}
	var p map[string]any
	if err := json.Unmarshal(fact.Payload, &p); err != nil {
		t.Fatal(err)
	}
	summary, _ := p["summary"].(string)
	if !strings.Contains(summary, "未留下结论") {
		t.Errorf("summary = %q, want it to say the run left no conclusion", summary)
	}
	if !strings.Contains(summary, "模型") && !strings.Contains(summary, "API") {
		t.Errorf("summary = %q, want it to carry the terminal reason so the planner knows "+
			"whether the route was tested at all", summary)
	}
	if strings.Contains(summary, "死路") || strings.Contains(summary, "不可利用") {
		t.Errorf("summary = %q must not read as a verdict on the target — nothing was tested", summary)
	}
}

// TestRunAbortedByCaller pins the predicate both terminalText and the wrap-up write-back
// share, so the two cannot drift apart on what "the caller stopped it" means.
func TestRunAbortedByCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	live, liveCancel := context.WithCancel(context.Background())
	defer liveCancel()

	cases := []struct {
		name   string
		ctx    context.Context
		reason harness.TerminalReason
		want   bool
	}{
		{"killed in a tool", live, harness.ReasonAbortedTools, true},
		{"killed mid-stream", live, harness.ReasonAbortedStreaming, true},
		{"cancelled, no terminal event", ctx, "", true},
		{"finished normally", live, harness.ReasonCompleted, false},
		{"ran out of turns", live, harness.ReasonMaxTurns, false},
		{"hit the wall clock", live, harness.ReasonTimeout, false},
		{"provider blew up", live, harness.ReasonModelError, false},
	}
	for _, c := range cases {
		if got := runAbortedByCaller(c.ctx, c.reason); got != c.want {
			t.Errorf("%s: runAbortedByCaller = %v, want %v", c.name, got, c.want)
		}
	}
}
