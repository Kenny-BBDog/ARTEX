package db

import "testing"

// TestTaskDepthCountsOnlyTheWorkersOwnVerdicts pins the route-depth rollup, including the
// rule that thin/premature are computed over `done` intents only. The system has no state
// for "the worker decided this path is dead" — a route that is abandoned early ends
// 'done' like any other — so 'exhausted' (ran out of room), 'blocked' (errored) and
// 'stopped' (killed) must not be mistaken for giving up.
func TestTaskDepthCountsOnlyTheWorkersOwnVerdicts(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", t)
	}
	defer d.Close()

	task, err := d.CreateTask("depth", "route depth fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	exp := d.Exploration(task.ExplorationID)

	// mk builds one intent in the given terminal state, gives it `attempts` tool calls,
	// and yields one fact stamped with `confidence` (empty = no fact at all).
	mk := func(state string, attempts int, confidence string) int64 {
		id, err := exp.AddNode(KindIntent, map[string]any{"summary": "route"}, 0, state, "worker", nil)
		if err != nil {
			t.Fatalf("intent node (%s): %v", state, err)
		}
		for i := 0; i < attempts; i++ {
			if _, err := d.Exec(`INSERT INTO activity(exploration_id, node_id, kind) VALUES ($1,$2,'tool_use')`,
				task.ExplorationID, id); err != nil {
				t.Fatalf("activity: %v", err)
			}
		}
		if confidence == "" {
			return id
		}
		fact, err := exp.AddNode(KindFact, map[string]any{"summary": "conclusion", "confidence": confidence}, 0, "confirmed", "worker", nil)
		if err != nil {
			t.Fatalf("fact node: %v", err)
		}
		if err := exp.Link(id, RelYields, fact); err != nil {
			t.Fatalf("yields edge: %v", err)
		}
		return id
	}

	deep, err := exp.AddNode(KindIntent, map[string]any{"summary": "deep route"}, 0, "done", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := d.Exec(`INSERT INTO activity(exploration_id, node_id, kind) VALUES ($1,$2,'tool_use')`,
			task.ExplorationID, deep); err != nil {
			t.Fatal(err)
		}
	}
	deepFact, err := exp.AddNode(KindFact, map[string]any{"confidence": "observed"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.Link(deep, RelYields, deepFact); err != nil {
		t.Fatal(err)
	}
	deepClaim, err := exp.AddNode(KindFinding, map[string]any{"summary": "found"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.Link(deep, RelYields, deepClaim); err != nil {
		t.Fatal(err)
	}

	mk("done", 1, "observed")      // thin AND stamped observed with nothing to show for it
	mk("done", 1, "inferred")      // thin but honest — admits the means were not exhausted
	mk("done", 1, "")              // thin, no conclusion recorded at all
	mk("exhausted", 1, "observed") // ran out of room; NOT the worker giving up
	mk("blocked", 1, "observed")   // errored
	mk("stopped", 1, "observed")   // killed externally

	dp, err := exp.TaskDepth()
	if err != nil {
		t.Fatal(err)
	}
	if dp.RoutesTerminal != 7 {
		t.Errorf("RoutesTerminal = %d, want 7 (deep + 6)", dp.RoutesTerminal)
	}
	if dp.RoutesDone != 4 {
		t.Errorf("RoutesDone = %d, want 4 (deep + the three done routes); "+
			"exhausted/blocked/stopped are not the worker's verdict", dp.RoutesDone)
	}
	if dp.RoutesThin != 3 {
		t.Errorf("RoutesThin = %d, want 3 — the deep route has 5 attempts", dp.RoutesThin)
	}
	if dp.RoutesYielding != 1 {
		t.Errorf("RoutesYielding = %d, want 1 (only the deep route yielded a finding)", dp.RoutesYielding)
	}
	// Facts from non-done routes must not be counted: only deep(observed), thin-inferred,
	// thin-observed are in scope. The exhausted/blocked/stopped facts are out.
	if dp.FactsObserved != 2 {
		t.Errorf("FactsObserved = %d, want 2 (deep + the thin observed one)", dp.FactsObserved)
	}
	if dp.FactsInferred != 1 {
		t.Errorf("FactsInferred = %d, want 1", dp.FactsInferred)
	}
	if dp.PrematureExhaustion != 1 {
		t.Errorf("PrematureExhaustion = %d, want 1 — barely touched, no finding, yet stamped observed",
			dp.PrematureExhaustion)
	}
	if len(dp.ThinRoutes) != 3 {
		t.Fatalf("ThinRoutes = %+v, want the 3 thin done routes", dp.ThinRoutes)
	}
	for _, r := range dp.ThinRoutes {
		if r.State != "done" {
			t.Errorf("a %s route leaked into ThinRoutes: %+v", r.State, r)
		}
	}

	// An exploration with no intents reports a clean zero, not an error.
	bare, err := d.CreateTask("depth-bare", "no intents", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(bare.ID) })
	none, err := d.Exploration(bare.ExplorationID).TaskDepth()
	if err != nil {
		t.Fatal(err)
	}
	if none.RoutesTerminal != 0 || none.PrematureExhaustion != 0 || len(none.ThinRoutes) != 0 {
		t.Errorf("empty exploration: %+v, want all zero", none)
	}
}
