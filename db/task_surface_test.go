package db

import (
	"fmt"
	"testing"
)

// TestUntouchedSurfaceCountsOnlyNeverWorkedAssets pins the definition of "touched": an
// asset carries a fact OR a finding anchor. The finding half matters — measured on the
// Juice Shop run, 2 of 41 assets produced a finding without a separate fact node, and
// calling those "untouched" would put them in a wrap-up checklist they do not belong in.
func TestUntouchedSurfaceCountsOnlyNeverWorkedAssets(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", t)
	}
	defer d.Close()

	task, err := d.CreateTask("surface", "untouched surface fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	expl := d.Exploration(task.ExplorationID)
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	mk := func(suffix string) int64 {
		t.Helper()
		id, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{
			Domain: fmt.Sprintf("surface-%s-%d.invalid", suffix, task.ID), TaskID: task.ID})
		if err != nil {
			t.Fatalf("upsert %s: %v", suffix, err)
		}
		return id
	}
	withFact, withFinding, never := mk("fact"), mk("finding"), mk("never")
	t.Cleanup(func() { _, _ = d.Assets().DeleteByIDs([]int64{withFact, withFinding, never}) })

	if _, err := expl.AddNode(KindFact, map[string]any{"summary": "observed"}, 0, "confirmed", "worker", []int64{withFact}); err != nil {
		t.Fatal(err)
	}
	findingNode, err := expl.AddNode(KindFinding, map[string]any{"summary": "found"}, 0, "confirmed", "worker", []int64{withFinding})
	if err != nil {
		t.Fatal(err)
	}
	_ = findingNode

	us, err := expl.UntouchedSurface(10)
	if err != nil {
		t.Fatal(err)
	}
	if us.Untouched != 1 {
		t.Errorf("Untouched = %d, want 1 (only the never-worked asset)", us.Untouched)
	}
	if len(us.Sample) != 1 || us.Sample[0].ID != never {
		t.Errorf("Sample = %+v, want exactly the never-worked asset id=%d", us.Sample, never)
	}

	// A task with no budget reports nil rather than a meaningless "left over" share.
	if us.BudgetLeftPct != nil {
		t.Errorf("BudgetLeftPct = %v for an unlimited task, want nil", *us.BudgetLeftPct)
	}

	// The waiver round-trips and clears.
	if r, err := expl.SurfaceWaiver(); err != nil || r != "" {
		t.Fatalf("initial waiver = %q err=%v, want empty", r, err)
	}
	if err := expl.SetSurfaceWaiver("装饰性资产，不推进"); err != nil {
		t.Fatal(err)
	}
	if r, err := expl.SurfaceWaiver(); err != nil || r != "装饰性资产，不推进" {
		t.Fatalf("waiver = %q err=%v", r, err)
	}
	if err := expl.SetSurfaceWaiver(""); err != nil {
		t.Fatal(err)
	}
	if r, _ := expl.SurfaceWaiver(); r != "" {
		t.Fatalf("waiver = %q after clearing, want empty", r)
	}
}
