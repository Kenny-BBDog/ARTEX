package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// setVerifierAgent makes the verifier agent exist or not. The agent package's tests share
// one database, so each test states the configuration it needs instead of assuming one.
func setVerifierAgent(t *testing.T, d *db.DB, present bool) {
	t.Helper()
	existing, err := d.GetAgentByKey(db.VerifierAgentKey)
	if err != nil {
		t.Fatal(err)
	}
	if present && existing == nil {
		if _, err := d.CreateAgent(db.VerifierAgentKey, "漏洞验证", "test verifier"); err != nil {
			t.Fatal(err)
		}
	}
	if !present && existing != nil {
		if err := d.DeleteAgent(db.VerifierAgentKey); err != nil {
			t.Fatal(err)
		}
	}
}

// proveGoalFixture builds a task with one goal and one reported finding, and returns a
// planner toolset plus the goal and finding NODE ids.
func proveGoalFixture(t *testing.T) (*db.DB, *ToolSet, int64, int64) {
	t.Helper()
	d := testDB(t)
	task, err := d.CreateTask("verification gate", "prove a goal from a finding", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	ts := d.Exploration(task.ExplorationID)
	goalID, err := ts.AddGoal(map[string]any{"text": "找到一个漏洞"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	// The real report_finding path, so the finding row is created exactly as a worker
	// would create it (status candidate).
	recorded, err := ts.RecordFinding(context.Background(), db.RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "sqli", Name: "SQL 注入", Severity: db.SeverityHigh,
		Summary: "user 参数可注入", Evidence: "curl ... 返回 SQL 报错", Worker: "work#1",
	})
	if err != nil {
		t.Fatal(err)
	}

	tools := NewToolSet(ts, "planner")
	tools.SetTaskID(task.ID)
	return d, tools, goalID, recorded.NodeID
}

// callProveGoal invokes the prove_goal tool and returns its flattened output.
func callProveGoal(t *testing.T, tools *ToolSet, goalID, evidenceID int64) (string, bool) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"goal_id": goalID, "evidence_id": evidenceID, "reason": "test"})
	res, err := tools.proveGoal().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("prove_goal Call error: %v", err)
	}
	text := res.Flatten()
	return text, res.IsError
}

// TestProveGoalRejectsUnverifiedFinding is the gate itself: a worker's own word is not
// enough to mark a goal met, because that also ends the task and cancels every running
// worker.
func TestProveGoalRejectsUnverifiedFinding(t *testing.T) {
	d, tools, goalID, findingNodeID := proveGoalFixture(t)
	setVerifierAgent(t, d, true)

	text, isErr := callProveGoal(t, tools, goalID, findingNodeID)
	if !isErr {
		t.Fatalf("prove_goal accepted an unverified candidate finding; output: %s", text)
	}
	if !strings.Contains(text, "独立验证") {
		t.Errorf("rejection should tell the planner what to do, got: %s", text)
	}

	// The goal must be untouched — a rejected proof leaves no trace.
	goal, err := tools.ts.GetNode(goalID)
	if err != nil || goal == nil {
		t.Fatalf("read goal: %v", err)
	}
	if goal.State == "met" {
		t.Fatal("rejected prove_goal still marked the goal met")
	}
}

// TestProveGoalAcceptsConfirmedFinding: once verification promotes the finding, the same
// call succeeds.
func TestProveGoalAcceptsConfirmedFinding(t *testing.T) {
	d, tools, goalID, findingNodeID := proveGoalFixture(t)
	setVerifierAgent(t, d, true)
	findingID, err := d.FindingIDByNodeID(findingNodeID)
	if err != nil || findingID == 0 {
		t.Fatalf("FindingIDByNodeID: id=%d err=%v", findingID, err)
	}
	if err := d.RecordFindingVerification(context.Background(), findingID,
		db.VerdictConfirmed, "独立复现成功", "换一条路径触发，回显一致", db.VerifierAgentKey, nil); err != nil {
		t.Fatal(err)
	}

	text, isErr := callProveGoal(t, tools, goalID, findingNodeID)
	if isErr {
		t.Fatalf("prove_goal rejected a confirmed finding; output: %s", text)
	}
	goal, err := tools.ts.GetNode(goalID)
	if err != nil || goal == nil {
		t.Fatalf("read goal: %v", err)
	}
	if goal.State != "met" {
		t.Fatalf("goal state = %q, want met", goal.State)
	}
}

// TestProveGoalEscapeHatchWithoutVerifier pins the deliberate fallback: with no verifier
// agent configured nothing would ever promote a candidate, so refusing one would deadlock
// every finding-based goal. Behaviour must stay exactly as it was before this feature.
func TestProveGoalEscapeHatchWithoutVerifier(t *testing.T) {
	d, tools, goalID, findingNodeID := proveGoalFixture(t)
	setVerifierAgent(t, d, false)

	text, isErr := callProveGoal(t, tools, goalID, findingNodeID)
	if isErr {
		t.Fatalf("with no verifier configured, prove_goal must keep the old behaviour; got: %s", text)
	}
	goal, err := tools.ts.GetNode(goalID)
	if err != nil || goal == nil {
		t.Fatalf("read goal: %v", err)
	}
	if goal.State != "met" {
		t.Fatalf("goal state = %q, want met", goal.State)
	}
}

// TestProveGoalAllowsFactEvidence: the gate is about findings only. Facts carry their own
// observed/inferred confidence and keep working as proof.
func TestProveGoalAllowsFactEvidence(t *testing.T) {
	d, tools, goalID, _ := proveGoalFixture(t)
	setVerifierAgent(t, d, true)
	factID, err := tools.ts.AddNode(db.KindFact, map[string]any{"summary": "目标已达成，回显证据见 detail"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if text, isErr := callProveGoal(t, tools, goalID, factID); isErr {
		t.Fatalf("fact evidence should still prove a goal; got: %s", text)
	}
}

// TestProveGoalAcceptsDisownedFindingNode covers a finding NODE with no findings row
// (test fixtures, legacy data): there is nothing to verify, so it is not blocked.
func TestProveGoalAcceptsDisownedFindingNode(t *testing.T) {
	d, tools, goalID, _ := proveGoalFixture(t)
	setVerifierAgent(t, d, true)
	bareNode, err := tools.ts.AddNode(db.KindFinding, map[string]any{"summary": "no findings row"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if text, isErr := callProveGoal(t, tools, goalID, bareNode); isErr {
		t.Fatalf("finding node without a findings row should not be blocked; got: %s", text)
	}
}
