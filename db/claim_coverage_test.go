package db

import (
	"fmt"
	"testing"
)

// TestTaskClaimCoverageCrossProduct pins the reached × claimed cross-product — the
// measurement the flywheel turns on. It builds one asset per cell of the 2×2 so the
// whole grid is asserted in a single call:
//
//	A: reached, claimed, and the claim survived verification
//	B: reached, claimed, but only a candidate (a false positive in the making)
//	C: reached, and then nothing was ever asserted  ← the silent miss
//	D: never reached at all
//
// C is the cell that matters most: it is only computable while "reached" (fact anchors)
// and "claimed" (finding anchors) stay independent records. If the exploration graph's
// node state were ever made to mirror findings.status, this test could not exist and the
// signal would be gone by construction.
func TestTaskClaimCoverageCrossProduct(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", t)
	}
	defer d.Close()

	task, err := d.CreateTask("claim-cov", "cross-product fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	assets := d.Assets()
	exp := d.Exploration(task.ExplorationID)

	mk := func(suffix string) (int64, string) {
		domain := fmt.Sprintf("claimcov-%s-%d.invalid", suffix, task.ID)
		id, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: domain, TaskID: task.ID})
		if err != nil {
			t.Fatalf("upsert %s: %v", domain, err)
		}
		if _, err := assets.AddAgentScope(task.ID, "root_domain", domain, "test", "agent"); err != nil {
			t.Fatalf("scope %s: %v", domain, err)
		}
		return id, domain
	}
	idA, _ := mk("a")
	idB, _ := mk("b")
	idC, _ := mk("c")
	idD, _ := mk("d")

	t.Cleanup(func() {
		_ = d.DeleteTask(task.ID)
		_, _ = assets.DeleteByIDs([]int64{idA, idB, idC, idD})
	})

	// "reached" = anchored to a fact. D gets none.
	for _, spec := range []struct {
		id   int64
		note string
	}{{idA, "observed A"}, {idB, "observed B"}, {idC, "observed C"}} {
		if _, err := exp.AddNode(KindFact, map[string]any{"summary": spec.note}, 0, "confirmed", "worker", []int64{spec.id}); err != nil {
			t.Fatalf("fact node for asset %d: %v", spec.id, err)
		}
	}

	// "claimed" = anchored to a finding node. C gets none — that is the silent miss.
	nodeA, err := exp.AddNode(KindFinding, map[string]any{"summary": "A: confirmed claim"}, 0, "confirmed", "worker", []int64{idA})
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := exp.AddNode(KindFinding, map[string]any{"summary": "B: candidate claim"}, 0, "confirmed", "worker", []int64{idB})
	if err != nil {
		t.Fatal(err)
	}
	// AddFinding defaults to candidate; only A is promoted, so B stays a false-positive
	// candidate and must NOT count toward ClaimedConfirmedAssets.
	fidA, err := d.AddFinding(task.ID, nodeA, "xss", "A", SeverityHigh, "s", "e", "worker", []int64{idA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddFinding(task.ID, nodeB, "sqli", "B", SeverityLow, "s", "e", "worker", []int64{idB}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(fidA, FindingConfirmed); err != nil {
		t.Fatal(err)
	}

	cc, err := assets.TaskClaimCoverage(task.ID, task.ExplorationID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if cc.Scope != 4 {
		t.Errorf("Scope = %d, want 4", cc.Scope)
	}
	if cc.Reached != 3 {
		t.Errorf("Reached = %d, want 3 (A, B, C have facts; D does not)", cc.Reached)
	}
	if cc.Claimed != 2 {
		t.Errorf("Claimed = %d, want 2 (A and B)", cc.Claimed)
	}
	if cc.Confirmed != 1 {
		t.Errorf("Confirmed = %d, want 1 (only A was verified; B is still candidate)", cc.Confirmed)
	}
	if cc.Silent != 1 {
		t.Errorf("Silent = %d, want 1 (C was reached and never asserted on)", cc.Silent)
	}
	if len(cc.SilentAssets) != 1 || cc.SilentAssets[0].ID != idC {
		t.Errorf("SilentAssets = %+v, want exactly the C asset id=%d", cc.SilentAssets, idC)
	}

	// The silent sample is capped, but Silent stays exact — the count is the metric, the
	// list is only a seed for the next run.
	capped, err := assets.TaskClaimCoverage(task.ID, task.ExplorationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if capped.Silent != 1 || len(capped.SilentAssets) != 1 {
		t.Errorf("cap applied wrongly: silent=%d list=%d", capped.Silent, len(capped.SilentAssets))
	}

	// An asset that is reached but out of scope must not appear anywhere: the whole
	// cross-product is computed over the authorization denominator, never the raw table.
	outID, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: fmt.Sprintf("outside-%d.invalid", task.ID), TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{outID}) })
	if _, err := exp.AddNode(KindFact, map[string]any{"summary": "outside scope"}, 0, "confirmed", "worker", []int64{outID}); err != nil {
		t.Fatal(err)
	}
	after, err := assets.TaskClaimCoverage(task.ID, task.ExplorationID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if after.Scope != 4 || after.Reached != 3 || after.Silent != 1 {
		t.Errorf("out-of-scope anchor leaked into the cross-product: %+v (want scope=4 reached=3 silent=1)", after)
	}
}
