package db

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"
)

// outcomeDB opens the test database with llm_usage present. That table lives in the
// Go-embedded DDL rather than schema.sql (EnsureLLMUsageTable, called from the server's
// Manager constructor), so a bare Open — which only runs schema.sql — does not have it.
// The outcome aggregation reads it, so tests must mirror the production ordering.
func outcomeDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		d.Close()
		t.Fatalf("ensure llm_usage: %v", err)
	}
	return d
}

// claimSilentAssetID is set by outcomeFixture to the asset it deliberately reaches
// without asserting anything on, so the cross-product assertion can name it exactly.
var claimSilentAssetID int64

// outcomeFixture builds one terminal task with data in every table the outcome
// aggregation reads, so a single assertion can cover the whole metric surface.
func outcomeFixture(t *testing.T) (*DB, *Task) {
	t.Helper()
	d := outcomeDB(t)
	task, err := d.CreateTask("outcome-fixture", "prove the outcome aggregates", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM task_outcome WHERE task_id=$1`, task.ID)
		_ = d.DeleteTask(task.ID)
		d.Close()
	})
	exp := task.ExplorationID

	// token 账本：两次调用，含一次失败。
	if _, err := d.Exec(`
INSERT INTO llm_usage(exploration_id, task_id, worker, model, input_tokens, output_tokens, cache_read, cache_write, status)
VALUES ($1,$2,'planner','m',100,20,5,7,'ok'), ($1,$2,'work#1','m',50,10,0,0,'error')`,
		exp, strconv.FormatInt(task.ID, 10)); err != nil {
		t.Fatal(err)
	}
	// 目标：两个，一个 met。
	if _, err := d.Exec(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, state)
VALUES ($1,'goal','{}','met'), ($1,'goal','{}','open')`, exp); err != nil {
		t.Fatal(err)
	}
	// 活动：2 次工具调用、1 次失败、3 次空转。
	if _, err := d.Exec(`
INSERT INTO activity(exploration_id, kind, is_error)
VALUES ($1,'tool_use',false), ($1,'tool_use',false), ($1,'tool_result',true),
       ($1,'empty_turn',false), ($1,'empty_turn',false), ($1,'empty_turn',false)`, exp); err != nil {
		t.Fatal(err)
	}
	// 漏洞：3 条，其中 1 条已验证、1 条误报；等级 high/critical/low。
	f1, err := d.AddFinding(task.ID, 0, "sqli", "SQLi", SeverityHigh, "s", "e", "work#1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddFinding(task.ID, 0, "rce", "RCE", SeverityCritical, "s", "e", "work#1", nil); err != nil {
		t.Fatal(err)
	}
	f3, err := d.AddFinding(task.ID, 0, "info", "Info", SeverityLow, "s", "e", "work#1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RecordFindingVerification(context.Background(), f1, VerdictConfirmed, "复现成功", "证据", VerifierAgentKey, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(f3, FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	// 复测：1 条判已修复。
	if _, err := d.Exec(`
INSERT INTO finding_retests(finding_id, status, verdict, snapshot)
VALUES ($1,'completed','fixed','{}')`, f1); err != nil {
		t.Fatal(err)
	}

	// reached × claimed 交叉度量：两个范围内资产都「到过」(有 fact 锚点)，其中只有一个
	// 被「说了」(有 finding 锚点)。剩下一格就是静默漏报——本 fixture 的 silent 样本。
	assets := d.Assets()
	expStore := d.Exploration(exp)
	claimedDomain := fmt.Sprintf("outcome-claimed-%d.invalid", task.ID)
	silentDomain := fmt.Sprintf("outcome-silent-%d.invalid", task.ID)
	claimedAsset, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: claimedDomain, TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	silentAsset, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: silentDomain, TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	claimSilentAssetID = silentAsset
	for _, dom := range []string{claimedDomain, silentDomain} {
		if _, err := assets.AddAgentScope(task.ID, "root_domain", dom, "test", "agent"); err != nil {
			t.Fatal(err)
		}
	}
	for _, aid := range []int64{claimedAsset, silentAsset} {
		if _, err := expStore.AddNode(KindFact, map[string]any{"summary": "observed"}, 0, "confirmed", "worker", []int64{aid}); err != nil {
			t.Fatal(err)
		}
	}
	findingNode, err := expStore.AddNode(KindFinding, map[string]any{"summary": "claims the claimed asset"}, 0, "confirmed", "worker", []int64{claimedAsset})
	if err != nil {
		t.Fatal(err)
	}
	// Reuse f1 rather than adding a row: findings_claimed is asserted as 3 above.
	if _, err := d.Exec(`UPDATE findings SET node_id=$1 WHERE id=$2`, findingNode, f1); err != nil {
		t.Fatal(err)
	}

	// 终态 + 首跑时间（duration 从 first_run_at 起算）。
	back := time.Now().Add(-3 * time.Hour)
	if _, err := d.Exec(`UPDATE tasks SET first_run_at=$1 WHERE id=$2`, back, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.SetStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	return d, task
}

func TestComputeAndStoreTaskOutcome(t *testing.T) {
	d, task := outcomeFixture(t)
	ctx := context.Background()

	o, err := d.ComputeTaskOutcome(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if o == nil {
		t.Fatal("no outcome for an existing task")
	}

	if o.LLMCalls != 2 || o.InputTokens != 150 || o.OutputTokens != 30 || o.CacheReadTokens != 5 || o.CacheWriteTokens != 7 {
		t.Fatalf("token metrics wrong (must come from llm_usage, failed calls included): %+v", o)
	}
	if o.GoalsTotal != 2 || o.GoalsMet != 1 {
		t.Fatalf("goals = %d/%d, want 1/2", o.GoalsMet, o.GoalsTotal)
	}
	// claimed counts every report; confirmed counts only what verification upheld.
	if o.FindingsClaimed != 3 || o.FindingsConfirmed != 1 {
		t.Fatalf("findings claimed=%d confirmed=%d, want 3/1", o.FindingsClaimed, o.FindingsConfirmed)
	}
	if o.FindingsFalsePositive != 1 {
		t.Fatalf("findings_false_positive = %d, want 1", o.FindingsFalsePositive)
	}
	if o.FindingsCritical != 1 || o.FindingsHigh != 1 || o.FindingsMedium != 0 || o.FindingsLow != 1 {
		t.Fatalf("severity breakdown wrong: %+v", o)
	}
	if o.RetestsFixed != 1 {
		t.Fatalf("retests_fixed = %d, want 1", o.RetestsFixed)
	}
	if o.ToolCalls != 2 || o.ToolErrors != 1 {
		t.Fatalf("tool calls=%d errors=%d, want 2/1", o.ToolCalls, o.ToolErrors)
	}
	if o.IdleTurns != 3 {
		t.Fatalf("idle_turns = %d, want 3", o.IdleTurns)
	}
	if o.DurationSeconds < 3*3600-5 || o.DurationSeconds > 3*3600+60 {
		t.Fatalf("duration = %ds, want ≈3h (measured from first_run_at)", o.DurationSeconds)
	}

	// The reached × claimed cross-product rides along on the same row. The fixture
	// reaches two assets (fact-anchored, = coverage_tested) and asserts on one of them,
	// leaving exactly one silent asset — see claimFixture.
	if o.CoverageTested != 2 {
		t.Fatalf("coverage_tested = %d, want 2 (the reached leg)", o.CoverageTested)
	}
	if o.ClaimedAssets != 1 || o.ClaimedConfirmedAssets != 1 {
		t.Fatalf("claimed=%d claimed_confirmed=%d, want 1/1", o.ClaimedAssets, o.ClaimedConfirmedAssets)
	}
	if o.SilentAssets != 1 {
		t.Fatalf("silent_assets = %d, want 1 (reached 2, claimed 1)", o.SilentAssets)
	}
	if len(o.SilentAssetList) != 1 || o.SilentAssetList[0].ID != claimSilentAssetID {
		t.Fatalf("silent_asset_list = %+v, want the one silent asset id=%d", o.SilentAssetList, claimSilentAssetID)
	}

	if err := d.UpsertTaskOutcome(ctx, o); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetTaskOutcome(task.ID)
	if err != nil || got == nil {
		t.Fatalf("GetTaskOutcome: %+v err=%v", got, err)
	}
	if got.FindingsClaimed != o.FindingsClaimed || got.InputTokens != o.InputTokens || got.IdleTurns != o.IdleTurns {
		t.Fatalf("round-trip mismatch: stored=%+v computed=%+v", got, o)
	}

	// Upsert must be idempotent — the sweep can recompute the same task.
	if err := d.UpsertTaskOutcome(ctx, o); err != nil {
		t.Fatal(err)
	}
	if n := countOutcomes(t, d, task.ID); n != 1 {
		t.Fatalf("upsert left %d rows, want 1", n)
	}
}

func TestComputeTaskOutcomeMissingTask(t *testing.T) {
	d, _ := outcomeFixture(t)
	o, err := d.ComputeTaskOutcome(context.Background(), 1<<40)
	if err != nil || o != nil {
		t.Fatalf("missing task should yield (nil, nil), got %+v err=%v", o, err)
	}
}

// TestTasksNeedingOutcomeRespectsGraceAndFreshness covers the sweep's selection rule: only
// terminal tasks past the grace period whose outcome is missing or older than completion.
func TestTasksNeedingOutcomeRespectsGraceAndFreshness(t *testing.T) {
	d, task := outcomeFixture(t)
	ctx := context.Background()

	// completed just now → inside the grace window → not selected.
	ids, err := d.TasksNeedingOutcome(30*time.Second, 50)
	if err != nil {
		t.Fatal(err)
	}
	if containsID(ids, task.ID) {
		t.Fatal("a task completed moments ago was selected despite the settle grace period")
	}

	// Past the grace period with no outcome row → selected.
	ids, err = d.TasksNeedingOutcome(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !containsID(ids, task.ID) {
		t.Fatal("terminal task without an outcome row was not selected")
	}

	// A non-terminal task is never selected.
	if err := d.SetStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	ids, _ = d.TasksNeedingOutcome(0, 50)
	if containsID(ids, task.ID) {
		t.Fatal("a running task was selected for an outcome")
	}
	if err := d.SetStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}

	// Computed after completion → fresh, not selected again.
	o, err := d.ComputeTaskOutcome(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if o.CompletedAt != nil {
		o.ComputedAt = o.CompletedAt.Add(time.Second)
	}
	if err := d.UpsertTaskOutcome(ctx, o); err != nil {
		t.Fatal(err)
	}
	ids, _ = d.TasksNeedingOutcome(0, 50)
	if containsID(ids, task.ID) {
		t.Fatal("a freshly computed outcome was selected again")
	}
}

func TestListTaskOutcomesFiltersByStatus(t *testing.T) {
	d, task := outcomeFixture(t)
	ctx := context.Background()
	o, err := d.ComputeTaskOutcome(ctx, task.ID)
	if err != nil || o == nil {
		t.Fatalf("compute: %+v err=%v", o, err)
	}
	if err := d.UpsertTaskOutcome(ctx, o); err != nil {
		t.Fatal(err)
	}

	done, err := d.ListTaskOutcomes("done", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !containsOutcome(done, task.ID) {
		t.Fatal("done-filtered list omitted the task")
	}
	timeout, err := d.ListTaskOutcomes("timeout", 100)
	if err != nil {
		t.Fatal(err)
	}
	if containsOutcome(timeout, task.ID) {
		t.Fatal("timeout-filtered list included a done task")
	}
	all, err := d.ListTaskOutcomes("", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !containsOutcome(all, task.ID) {
		t.Fatal("unfiltered list omitted the task")
	}
}

func TestOutcomeSurvivesTaskDeletionCascade(t *testing.T) {
	d := outcomeDB(t)
	defer d.Close()
	task, err := d.CreateTask("cascade", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	o, err := d.ComputeTaskOutcome(context.Background(), task.ID)
	if err != nil || o == nil {
		t.Fatalf("compute: %+v err=%v", o, err)
	}
	if err := d.UpsertTaskOutcome(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTask(task.ID); err != nil {
		t.Fatal(err)
	}
	if n := countOutcomes(t, d, task.ID); n != 0 {
		t.Fatalf("deleting a task left %d orphan outcome rows", n)
	}
}

func countOutcomes(t *testing.T, d *DB, taskID int64) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM task_outcome WHERE task_id=$1`, taskID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func containsID(ids []int64, want int64) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func containsOutcome(list []*TaskOutcome, taskID int64) bool {
	for _, o := range list {
		if o.TaskID == taskID {
			return true
		}
	}
	return false
}
