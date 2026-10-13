package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// surfaceGateFixture builds a task that is otherwise ready to complete — one goal, one
// VERIFIED finding as its evidence — plus `untouched` discovered assets that were never
// worked on. Proving the single goal therefore also completes the task, which is the only
// moment the surface review applies.
func surfaceGateFixture(t *testing.T, untouched int, budgetSeconds int64) (*db.DB, *ToolSet, int64, int64) {
	t.Helper()
	d := testDB(t)
	setVerifierAgent(t, d, true)
	task, err := d.CreateTask("surface gate", "do not stop while surface remains", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	ts := d.Exploration(task.ExplorationID)
	goalID, err := ts.AddGoal(map[string]any{"text": "完成评估"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	// A confirmed finding, so the VERIFICATION gate is satisfied and cannot be what
	// rejects — the test has to isolate the surface gate.
	recorded, err := ts.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "sqli", Name: "SQL 注入", Severity: db.SeverityHigh,
		Summary: "user 参数可注入", Evidence: "curl ... 返回 SQL 报错", Worker: "work#1",
	})
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := d.FindingIDByNodeID(recorded.NodeID)
	if err != nil || findingID == 0 {
		t.Fatalf("FindingIDByNodeID: id=%d err=%v", findingID, err)
	}
	if err := d.RecordFindingVerification(context.Background(), findingID, db.VerdictConfirmed, "复现成功", "证据", db.VerifierAgentKey, nil); err != nil {
		t.Fatal(err)
	}

	// Discovered, owned, never touched.
	ids := make([]int64, 0, untouched)
	for i := 0; i < untouched; i++ {
		id, err := d.Assets().UpsertRootDomain(db.UpsertRootDomainReq{
			Domain: fmt.Sprintf("surface-gate-%d-%d.invalid", task.ID, i), TaskID: task.ID})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	t.Cleanup(func() { _, _ = d.Assets().DeleteByIDs(ids) })

	if budgetSeconds > 0 {
		if _, err := d.Exec(`UPDATE tasks SET timeout_seconds=$1 WHERE id=$2`, budgetSeconds, task.ID); err != nil {
			t.Fatal(err)
		}
	}

	tools := NewToolSet(ts, "planner")
	tools.SetTaskID(task.ID)
	return d, tools, goalID, recorded.NodeID
}

func callAcceptSurface(t *testing.T, tools *ToolSet, reason string) (string, bool) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"reason": reason})
	res, err := tools.acceptUntestedSurface().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("accept_untested_surface Call error: %v", err)
	}
	return res.Flatten(), res.IsError
}

// TestProveGoalRejectsWrapUpWithUntouchedSurface is the gate: proving the last goal while
// the run still owns discovered assets it never touched does not complete the task.
//
// This was measured on OWASP Juice Shop, where the run ended with 15 self-discovered
// assets untouched and 33% of its budget unspent — and nothing could see it, because the
// only remaining-work tool is bounded by a scope predicate that matched 1 of 41 assets.
func TestProveGoalRejectsWrapUpWithUntouchedSurface(t *testing.T) {
	_, tools, goalID, findingNodeID := surfaceGateFixture(t, 3, 2400)

	text, isErr := callProveGoal(t, tools, goalID, findingNodeID)
	if !isErr {
		t.Fatalf("prove_goal allowed wrap-up with 3 untouched discovered assets; output: %s", text)
	}
	if !strings.Contains(text, "从未触碰") || !strings.Contains(text, "accept_untested_surface") {
		t.Errorf("rejection must state the problem AND both ways out, got: %s", text)
	}
	goal, err := tools.ts.GetNode(goalID)
	if err != nil || goal == nil {
		t.Fatalf("read goal: %v", err)
	}
	if goal.State == "met" {
		t.Fatal("a rejected wrap-up still marked the goal met — the graph must be untouched")
	}
	if tools.GoalMet {
		t.Fatal("a rejected wrap-up still completed the task")
	}

	// Way out 1: an explicit waiver, recorded through the tool the message names.
	ack, isErr := callAcceptSurface(t, tools, "这些是装饰性资产，确认无法从本目标推进")
	if isErr {
		t.Fatalf("accept_untested_surface failed: %s", ack)
	}
	if reason, err := tools.ts.SurfaceWaiver(); err != nil || reason == "" {
		t.Fatalf("waiver not persisted: %q err=%v", reason, err)
	}
	text, isErr = callProveGoal(t, tools, goalID, findingNodeID)
	if isErr {
		t.Fatalf("prove_goal still rejected after an explicit waiver: %s", text)
	}
	if !tools.GoalMet {
		t.Fatal("prove_goal succeeded but the task was not completed")
	}
}

// TestProveGoalWrapUpAllowedWithNoUntouchedSurface: nothing left to look at, nothing to gate.
func TestProveGoalWrapUpAllowedWithNoUntouchedSurface(t *testing.T) {
	_, tools, goalID, findingNodeID := surfaceGateFixture(t, 0, 2400)
	if _, isErr := callProveGoal(t, tools, goalID, findingNodeID); isErr {
		t.Fatal("prove_goal was gated with no untouched surface at all")
	}
	if !tools.GoalMet {
		t.Fatal("task did not complete with no untouched surface")
	}
}

// TestProveGoalWrapUpAllowedWhenBudgetExhausted: running out of room is a legitimate
// ending, not a premature one — otherwise a run that spent everything could never finish.
func TestProveGoalWrapUpAllowedWhenBudgetExhausted(t *testing.T) {
	d, tools, goalID, findingNodeID := surfaceGateFixture(t, 3, 600)
	taskID, err := tools.ts.TaskID()
	if err != nil || taskID == 0 {
		t.Fatalf("task id: %d err=%v", taskID, err)
	}
	// Started long before the 600s budget, so nothing is left.
	if _, err := d.Exec(`UPDATE tasks SET first_run_at=now()-interval '2 hours' WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	us, err := tools.ts.UntouchedSurface(0)
	if err != nil || us == nil {
		t.Fatalf("untouched surface: %+v err=%v", us, err)
	}
	if us.BudgetLeftPct == nil || *us.BudgetLeftPct > 0 {
		t.Fatalf("precondition failed: budget_left_pct = %v, want 0", us.BudgetLeftPct)
	}
	if _, isErr := callProveGoal(t, tools, goalID, findingNodeID); isErr {
		t.Fatal("prove_goal was gated despite an exhausted budget — the run has no room to do more")
	}
}

// TestAcceptUntestedSurfaceRequiresReason: the waiver has to say something, or it is just
// the silent wrap-up it exists to replace.
func TestAcceptUntestedSurfaceRequiresReason(t *testing.T) {
	_, tools, _, _ := surfaceGateFixture(t, 1, 2400)
	if text, isErr := callAcceptSurface(t, tools, "   "); !isErr {
		t.Fatalf("accept_untested_surface accepted an empty reason: %s", text)
	}
	if reason, _ := tools.ts.SurfaceWaiver(); reason != "" {
		t.Fatalf("an empty reason was persisted: %q", reason)
	}
}

// TestProveGoalAllowsWrapUpLateInTheBudget is the narrowing. The unconditional gate cost
// 60% more compute for zero recall gain on the Juice Shop re-run, because "do not stop
// yet" resolves to "keep working the surface you are on". Past the halfway point, stopping
// and running out are the same thing, so the gate stands down.
func TestProveGoalAllowsWrapUpLateInTheBudget(t *testing.T) {
	d, tools, goalID, findingNodeID := surfaceGateFixture(t, 3, 600)
	taskID, _ := tools.ts.TaskID()
	// 500s into a 600s budget → ~17% left, below the threshold.
	if _, err := d.Exec(`UPDATE tasks SET first_run_at=now()-interval '500 seconds' WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	us, err := tools.ts.UntouchedSurface(0)
	if err != nil || us == nil || us.BudgetLeftPct == nil {
		t.Fatalf("precondition: %+v err=%v", us, err)
	}
	if *us.BudgetLeftPct > earlyExitBudgetLeft {
		t.Fatalf("precondition: budget_left_pct = %.2f, want <= %.2f", *us.BudgetLeftPct, earlyExitBudgetLeft)
	}
	if _, isErr := callProveGoal(t, tools, goalID, findingNodeID); isErr {
		t.Fatal("prove_goal was gated late in the budget — past halfway, stopping IS running out")
	}
}

// TestProveGoalAllowsWrapUpWithoutABudget: with no time budget there is no "early" to
// detect, and holding the task open would bill indefinitely.
func TestProveGoalAllowsWrapUpWithoutABudget(t *testing.T) {
	_, tools, goalID, findingNodeID := surfaceGateFixture(t, 3, 0)
	if _, isErr := callProveGoal(t, tools, goalID, findingNodeID); isErr {
		t.Fatal("prove_goal was gated on a task with no budget — nothing says it stopped early")
	}
}

// TestUntouchedSurfaceIgnoresAssetsClaimedByLiveIntents is the alignment fix. The planner
// de-duplicates by INTENT while the metric counted by ASSET, so the two disagreed — and on
// the Juice Shop re-run that disagreement made the gate fire three times over assets the
// planner had itself described as "already covered by open intents", burning the rest of
// the budget re-chewing the same surface for no extra recall.
func TestUntouchedSurfaceIgnoresAssetsClaimedByLiveIntents(t *testing.T) {
	d, tools, goalID, findingNodeID := surfaceGateFixture(t, 2, 2400)
	taskID, err := tools.ts.TaskID()
	if err != nil || taskID == 0 {
		t.Fatalf("task id: %d err=%v", taskID, err)
	}

	// Before: nothing is in flight, so both assets are genuinely unattended.
	us, err := tools.ts.UntouchedSurface(0)
	if err != nil || us == nil {
		t.Fatalf("untouched surface: %+v err=%v", us, err)
	}
	if us.Untouched != 2 {
		t.Fatalf("Untouched = %d, want 2 before any intent claims them", us.Untouched)
	}

	// An OPEN intent aimed at one of them: that asset is spoken for, not abandoned.
	// Scoped to THIS task: the agent package's tests share a database, so an unfiltered
	// "any linked asset" query picks up another test's fixture under the full suite.
	var assetID int64
	if err := d.QueryRow(`SELECT l.asset_id FROM task_asset_links l
		WHERE l.task_id = $1 ORDER BY l.asset_id LIMIT 1`, taskID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.ts.AddNode(db.KindIntent, map[string]any{"summary": "test this asset"}, 0, "open", "planner", []int64{assetID}); err != nil {
		t.Fatal(err)
	}
	us, err = tools.ts.UntouchedSurface(0)
	if err != nil || us == nil {
		t.Fatalf("untouched surface: %+v err=%v", us, err)
	}
	if us.Untouched != 1 {
		t.Fatalf("Untouched = %d, want 1 — an asset a live intent is aimed at is in flight, not unattended", us.Untouched)
	}

	// The OTHER asset is now claimed too, so nothing is left unattended and the gate stands
	// down — the wrap-up is no longer leaving anything on the table.
	var otherID int64
	if err := d.QueryRow(`SELECT l.asset_id FROM task_asset_links l
		WHERE l.task_id = $1 AND l.asset_id <> $2 ORDER BY l.asset_id LIMIT 1`,
		taskID, assetID).Scan(&otherID); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.ts.AddNode(db.KindIntent, map[string]any{"summary": "and this one"}, 0, "running", "planner", []int64{otherID}); err != nil {
		t.Fatal(err)
	}
	us, err = tools.ts.UntouchedSurface(0)
	if err != nil || us == nil {
		t.Fatalf("untouched surface: %+v err=%v", us, err)
	}
	if us.Untouched != 0 {
		t.Fatalf("Untouched = %d, want 0 — both assets are under live intents", us.Untouched)
	}
	if _, isErr := callProveGoal(t, tools, goalID, findingNodeID); isErr {
		t.Fatal("prove_goal was gated even though every discovered asset was in flight")
	}
}
