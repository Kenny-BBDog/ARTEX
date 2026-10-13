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

// gapAssetID is set by outcomeFixture to the asset it links to the task but deliberately
// leaves outside the scope predicate.
var gapAssetID int64

// thinIntentID is set by outcomeFixture to the barely-touched route it creates, so the
// thin_routes JSONB round-trip assertion can name it exactly.
var thinIntentID int64

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
	// 范围缺口：一个被关联、但自身范围覆盖不到的资产。它不进分母，所以既不算 silent
	// 也不进未测清单——必须单独数出来。来源标 agent：是 worker 自己插进来的。
	gapDomain := fmt.Sprintf("outcome-gap-%d.invalid", task.ID)
	gapAsset, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: gapDomain, TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assets.AttachAssetsToTask(task.ID, []int64{claimedAsset, silentAsset, gapAsset}, "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := assets.SetTaskAssetSource(task.ID, gapAsset, "agent", "fixture worker insert", nil); err != nil {
		t.Fatal(err)
	}
	gapAssetID = gapAsset
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

	// 路线深度：一条只动了一下、零漏洞、却把结论标成 observed 的路线 —— premature_exhaustion
	// 的那一格。它同时让 thin_routes 的 JSONB 往返有真实内容可测。
	thinIntent, err := expStore.AddNode(KindIntent, map[string]any{"summary": "thin route"}, 0, "done", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO activity(exploration_id, node_id, kind) VALUES ($1,$2,'tool_use')`,
		exp, thinIntent); err != nil {
		t.Fatal(err)
	}
	thinFact, err := expStore.AddNode(KindFact, map[string]any{"summary": "not injectable", "confidence": "observed"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := expStore.Link(thinIntent, RelYields, thinFact); err != nil {
		t.Fatal(err)
	}
	thinIntentID = thinIntent

	// 终态 + 首跑时间（duration 从 first_run_at 起算）+ 时间预算（广度度量要用）。
	back := time.Now().Add(-3 * time.Hour)
	if _, err := d.Exec(`UPDATE tasks SET first_run_at=$1, timeout_seconds=600 WHERE id=$2`, back, task.ID); err != nil {
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
	// 3 = the two seeded tool_use rows plus the one the thin route in this fixture ran.
	if o.ToolCalls != 3 || o.ToolErrors != 1 {
		t.Fatalf("tool calls=%d errors=%d, want 3/1", o.ToolCalls, o.ToolErrors)
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

	// The upstream gap: three assets linked, one of them outside the scope predicate, so it
	// never entered the denominator the two lines above are computed over.
	if o.LinkedAssets != 3 {
		t.Fatalf("linked_assets = %d, want 3", o.LinkedAssets)
	}
	if o.UncoveredAssets != 1 || o.UncoveredAgentAssets != 1 {
		t.Fatalf("uncovered=%d uncovered_agent=%d, want 1/1", o.UncoveredAssets, o.UncoveredAgentAssets)
	}
	if len(o.UncoveredAssetList) != 1 || o.UncoveredAssetList[0].ID != gapAssetID {
		t.Fatalf("uncovered_asset_list = %+v, want the gap asset id=%d", o.UncoveredAssetList, gapAssetID)
	}
	if o.UncoveredAssetList[0].Source != "agent" {
		t.Fatalf("gap asset source = %q, want agent (the provenance that makes the gap actionable)",
			o.UncoveredAssetList[0].Source)
	}

	// Route depth rides on the same row, and its JSONB list must survive the round-trip.
	if o.RoutesTerminal != 1 || o.RoutesDone != 1 || o.RoutesThin != 1 {
		t.Fatalf("routes terminal=%d done=%d thin=%d, want 1/1/1",
			o.RoutesTerminal, o.RoutesDone, o.RoutesThin)
	}
	if o.FactsObserved != 1 || o.FactsInferred != 0 {
		t.Fatalf("facts observed=%d inferred=%d, want 1/0", o.FactsObserved, o.FactsInferred)
	}
	if o.PrematureExhaustion != 1 {
		t.Fatalf("premature_exhaustion = %d, want 1", o.PrematureExhaustion)
	}
	if len(o.ThinRoutes) != 1 || o.ThinRoutes[0].IntentID != thinIntentID {
		t.Fatalf("thin_routes = %+v, want the one thin route id=%d", o.ThinRoutes, thinIntentID)
	}

	// Breadth: the run used 3h of a 10-minute budget, so it is well "over" — the clamp
	// must hold it at 0 rather than reporting a negative remainder.
	if o.BudgetSeconds != 600 {
		t.Fatalf("budget_seconds = %d, want 600", o.BudgetSeconds)
	}
	if o.BudgetLeftPct == nil || *o.BudgetLeftPct != 0 {
		t.Fatalf("budget_left_pct = %v, want 0 (3h run against a 600s budget, clamped)", o.BudgetLeftPct)
	}
	// The split must reconstruct the reached total exactly, and this fixture reaches two
	// linked assets — both anchored at the same moment, so both land on the same side.
	if o.ReachAtMidpoint+o.LateReachGrowth != o.AssetsReached {
		t.Fatalf("reach_at_midpoint(%d) + late_reach_growth(%d) != assets_reached(%d)",
			o.ReachAtMidpoint, o.LateReachGrowth, o.AssetsReached)
	}
	if o.AssetsReached != 2 {
		t.Fatalf("assets_reached = %d, want 2 (the fixture anchors two linked assets)", o.AssetsReached)
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

// TestTasksNeedingOutcomeRecomputesWhenAdjudicationLandsLate is the regression test for a
// staleness bug the T2 end-to-end run exposed: the outcome was computed 32s after the task
// finished, and the last verification landed 15s after that — so the row said
// confirmed=3 while the truth was 4, permanently, because the sweep only re-selected tasks
// whose computed_at predated completed_at. Verifier agents are triggered asynchronously,
// so adjudication routinely outlives the worker that reported the finding.
func TestTasksNeedingOutcomeRecomputesWhenAdjudicationLandsLate(t *testing.T) {
	d, task := outcomeFixture(t)
	ctx := context.Background()

	// A verification written now, with the outcome stamped as computed a minute ago.
	if _, err := d.Exec(`
INSERT INTO finding_verifications(finding_id, verdict, summary, evidence, agent, created_at)
SELECT id, 'confirmed', 'late', 'late', 'verifier', now() FROM findings WHERE task_id=$1 LIMIT 1`,
		task.ID); err != nil {
		t.Fatal(err)
	}
	o, err := d.ComputeTaskOutcome(ctx, task.ID)
	if err != nil || o == nil {
		t.Fatalf("compute: %+v err=%v", o, err)
	}
	o.ComputedAt = time.Now().Add(-time.Minute)
	if err := d.UpsertTaskOutcome(ctx, o); err != nil {
		t.Fatal(err)
	}

	ids, err := d.TasksNeedingOutcome(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !containsID(ids, task.ID) {
		t.Fatal("an outcome older than a later verification was not re-selected — " +
			"the confirmed count would freeze below the truth forever")
	}

	// Once computed past the newest adjudication write, it must settle.
	o.ComputedAt = time.Now().Add(time.Minute)
	if err := d.UpsertTaskOutcome(ctx, o); err != nil {
		t.Fatal(err)
	}
	ids, _ = d.TasksNeedingOutcome(0, 50)
	if containsID(ids, task.ID) {
		t.Fatal("a settled outcome was re-selected — the sweep would never converge")
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
