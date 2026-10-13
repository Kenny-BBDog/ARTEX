package db

import (
	"fmt"
	"testing"
	"time"
)

// mkBreadthAsset registers a root_domain asset against the task (which links it via the
// task_asset_links trigger) and returns its id and domain.
func mkBreadthAsset(t *testing.T, d *DB, assets *AssetStore, task *Task, suffix string) (int64, string) {
	t.Helper()
	domain := fmt.Sprintf("breadth-%s-%d.invalid", suffix, task.ID)
	id, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: domain, TaskID: task.ID})
	if err != nil {
		t.Fatalf("upsert %s: %v", domain, err)
	}
	return id, domain
}

// TestTaskBreadthSplitsReachAtTheMidpoint pins the breadth figures, whose job is to say
// whether a run stopped because the work was done or because it stopped looking. The
// discriminating number is LateReachGrowth: the new surface the SECOND half opened up.
//
// The universe is the task's own linked assets, NOT the scope-matched denominator — a
// run that discovered a large surface must not have its breadth figure shrunk by scope
// bookkeeping that failed to keep up.
func TestTaskBreadthSplitsReachAtTheMidpoint(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", t)
	}
	defer d.Close()

	task, err := d.CreateTask("breadth", "breadth fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	assets := d.Assets()
	exp := d.Exploration(task.ExplorationID)
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	early1, _ := mkBreadthAsset(t, d, assets, task, "early1")
	early2, _ := mkBreadthAsset(t, d, assets, task, "early2")
	late, _ := mkBreadthAsset(t, d, assets, task, "late")
	never, _ := mkBreadthAsset(t, d, assets, task, "never") // linked, never touched
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{early1, early2, late, never}) })

	start := time.Now().Add(-100 * time.Second)
	end := time.Now()
	if _, err := d.Exec(`UPDATE tasks SET first_run_at=$1, completed_at=$2, timeout_seconds=$3 WHERE id=$4`,
		start, end, 400, task.ID); err != nil {
		t.Fatal(err)
	}
	anchor := func(assetID int64, at time.Time) {
		t.Helper()
		node, err := exp.AddNode(KindFact, map[string]any{"summary": "observed"}, 0, "confirmed", "worker", []int64{assetID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE exploration_nodes SET created_at=$1 WHERE id=$2`, at, node); err != nil {
			t.Fatal(err)
		}
	}
	anchor(early1, start.Add(10*time.Second))
	anchor(early2, start.Add(20*time.Second))
	anchor(late, start.Add(80*time.Second)) // past the midpoint (start+50s)

	br, err := assets.TaskBreadth(task.ID, task.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	if br.AssetsReached != 3 {
		t.Errorf("AssetsReached = %d, want 3 (the never-touched asset has no anchor)", br.AssetsReached)
	}
	if br.ReachAtMidpoint != 2 {
		t.Errorf("ReachAtMidpoint = %d, want 2", br.ReachAtMidpoint)
	}
	if br.LateReachGrowth != 1 {
		t.Errorf("LateReachGrowth = %d, want 1 — the late asset belongs to the second half", br.LateReachGrowth)
	}
	if br.ReachAtMidpoint+br.LateReachGrowth != br.AssetsReached {
		t.Errorf("split does not reconstruct the total: %d + %d != %d",
			br.ReachAtMidpoint, br.LateReachGrowth, br.AssetsReached)
	}

	// used = 100s of a 400s budget → three quarters left.
	if br.BudgetSeconds != 400 {
		t.Errorf("BudgetSeconds = %d, want 400", br.BudgetSeconds)
	}
	if br.BudgetLeftPct == nil {
		t.Fatal("BudgetLeftPct is nil for a task with a budget")
	}
	if got := *br.BudgetLeftPct; got < 0.74 || got > 0.76 {
		t.Errorf("BudgetLeftPct = %.3f, want ≈0.75 (100s used of 400s)", got)
	}

	// An unlimited task has nothing to be "left over" from.
	if _, err := d.Exec(`UPDATE tasks SET timeout_seconds=0 WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	br, err = assets.TaskBreadth(task.ID, task.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	if br.BudgetLeftPct != nil {
		t.Errorf("BudgetLeftPct = %v for an unlimited task, want nil", *br.BudgetLeftPct)
	}
}
