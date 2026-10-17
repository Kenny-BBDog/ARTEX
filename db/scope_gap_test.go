package db

import (
	"fmt"
	"testing"
)

// TestTaskScopeGap pins the upstream leak: assets the task owns but its own scope
// predicate does not cover. Such an asset is worse than untested — it is uncountable.
// It never enters the coverage denominator, so it can never show up as a silent miss or
// in the untested backlog either. A scope that under-covers therefore hides precisely the
// misses the rest of the measurement exists to surface, which is why it is measured apart.
func TestTaskScopeGap(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", t)
	}
	defer d.Close()

	task, err := d.CreateTask("scope-gap", "gap fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	assets := d.Assets()

	mk := func(suffix string) (int64, string) {
		domain := fmt.Sprintf("scopegap-%s-%d.invalid", suffix, task.ID)
		id, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: domain, TaskID: task.ID})
		if err != nil {
			t.Fatalf("upsert %s: %v", domain, err)
		}
		return id, domain
	}
	covered, coveredDomain := mk("covered")
	agentGap, agentGapDomain := mk("agent-gap") // linked, out of scope, inserted by a worker
	systemGap, _ := mk("system-gap")            // linked, out of scope, associated by the platform

	// A global asset that names no task at all — it must never enter Linked, no matter how
	// it matches the scope predicate. Naming a TaskID is what associates an asset: the
	// trg_assets_task_links trigger creates the link row automatically, so any upsert that
	// passes a TaskID is linked by construction.
	unlinkedDomain := fmt.Sprintf("scopegap-unlinked-%d.invalid", task.ID)
	unlinked, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: unlinkedDomain})
	if err != nil {
		t.Fatal(err)
	}

	// Only one scope row, covering one of the four assets.
	if _, err := assets.AddAgentScope(task.ID, "root_domain", coveredDomain, "test", "agent"); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = d.DeleteTask(task.ID)
		_, _ = assets.DeleteByIDs([]int64{covered, agentGap, systemGap, unlinked})
	})

	// Provenance is what makes the gap actionable. covered/systemGap keep the trigger's
	// generic 'system'; only agentGap is marked as a worker's own insert.
	if err := assets.SetTaskAssetSource(task.ID, agentGap, "agent", "Worker 通过 insert_assets 登记", nil); err != nil {
		t.Fatal(err)
	}

	sg, err := assets.TaskScopeGap(task.ID, task.ExplorationID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if sg.Linked != 3 {
		t.Errorf("Linked = %d, want 3 (the unlinked asset must not count)", sg.Linked)
	}
	if sg.Uncovered != 2 {
		t.Errorf("Uncovered = %d, want 2 (agentGap + systemGap)", sg.Uncovered)
	}
	if sg.UncoveredAgent != 1 {
		t.Errorf("UncoveredAgent = %d, want 1 — the split is what separates an agent that "+
			"outgrew its scope from bookkeeping that fell behind", sg.UncoveredAgent)
	}
	if len(sg.UncoveredAssets) != 2 {
		t.Fatalf("UncoveredAssets = %+v, want both gap assets", sg.UncoveredAssets)
	}
	// Agent-sourced gaps sort first: they are the ones that need a human look.
	if sg.UncoveredAssets[0].ID != agentGap {
		t.Errorf("gap sample does not lead with the agent-sourced asset: %+v", sg.UncoveredAssets)
	}
	for _, a := range sg.UncoveredAssets {
		if a.ID == covered {
			t.Errorf("a covered asset leaked into the gap sample: %+v", a)
		}
	}
	if sg.UncoveredAssets[0].Source != "agent" {
		t.Errorf("source not carried through: %+v", sg.UncoveredAssets[0])
	}

	// Capping the sample must not move the counts.
	capped, err := assets.TaskScopeGap(task.ID, task.ExplorationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if capped.Uncovered != 2 || len(capped.UncoveredAssets) != 1 {
		t.Errorf("cap applied wrongly: uncovered=%d list=%d", capped.Uncovered, len(capped.UncoveredAssets))
	}

	// Widening the scope closes the gap — the metric tracks the predicate, not a snapshot.
	if _, err := assets.AddAgentScope(task.ID, "root_domain", agentGapDomain, "test", "agent"); err != nil {
		t.Fatal(err)
	}
	closed, err := assets.TaskScopeGap(task.ID, task.ExplorationID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Uncovered != 1 || closed.UncoveredAgent != 0 {
		t.Errorf("after scoping the agent-gap domain: uncovered=%d uncovered_agent=%d, want 1/0",
			closed.Uncovered, closed.UncoveredAgent)
	}

	// A task with nothing linked reports a clean zero rather than an error.
	empty, err := d.CreateTask("scope-gap-empty", "no assets", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(empty.ID) })
	none, err := assets.TaskScopeGap(empty.ID, empty.ExplorationID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if none.Linked != 0 || none.Uncovered != 0 || len(none.UncoveredAssets) != 0 {
		t.Errorf("empty task: %+v, want all zero", none)
	}
}
