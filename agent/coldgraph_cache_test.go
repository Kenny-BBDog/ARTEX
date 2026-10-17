package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// buildDelta runs fn and reports how many full-graph builds it caused, so a test can
// assert a cache HIT really avoided the load rather than just returning equal data.
func buildDelta(fn func()) uint64 {
	before := coldgraphBuilds.Load()
	fn()
	return coldgraphBuilds.Load() - before
}

// TestColdGraphSnapshotCacheReusesUntilGraphChanges pins the cache's contract: a
// snapshot is reused while the exploration's graph version is unchanged, and is
// rebuilt after each kind of write that can change it.
//
// The ClaimIntent case is the one worth spelling out: it moves a row from open to
// running without touching content_version or adding any row, yet the planner's
// overview renders open_intents/running_intents from that very state — which is why
// the cache keys on GraphVersion rather than on content_version.
func TestColdGraphSnapshotCacheReusesUntilGraphChanges(t *testing.T) {
	d := testDB(t)
	expID, err := d.CreateExploration("cache probe", "prove the cache invalidates")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	ts := d.Exploration(expID)

	// First load builds; an immediate second load must be served from the cache.
	if got := buildDelta(func() { _, _, _ = loadColdGraphCached(ts) }); got != 1 {
		t.Fatalf("first load built %d times, want 1", got)
	}
	if got := buildDelta(func() { _, _, _ = loadColdGraphCached(ts) }); got != 0 {
		t.Fatalf("second load rebuilt %d times, want 0 (cache miss)", got)
	}

	// A new node must invalidate.
	factID, err := ts.AddNode(db.KindFact, map[string]any{"summary": "a fact"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := buildDelta(func() { _, _, _ = loadColdGraphCached(ts) }); got != 1 {
		t.Fatalf("after AddNode: rebuilt %d times, want 1", got)
	}

	// A new edge must invalidate on its own (no new node involved).
	intentID, err := ts.AddIntent(map[string]any{"summary": "an intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if got := buildDelta(func() { _, _, _ = loadColdGraphCached(ts) }); got != 1 {
		t.Fatalf("after AddIntent: rebuilt %d times, want 1", got)
	}
	if err := ts.Link(intentID, db.RelYields, factID); err != nil {
		t.Fatal(err)
	}
	if got := buildDelta(func() { _, _, _ = loadColdGraphCached(ts) }); got != 1 {
		t.Fatalf("after Link: rebuilt %d times, want 1", got)
	}

	// open → running changes no row content, but readers render state from it.
	claimed, err := ts.ClaimIntent(intentID, "work#1")
	if err != nil || !claimed {
		t.Fatalf("ClaimIntent = %v, %v; want true, nil", claimed, err)
	}
	if got := buildDelta(func() { _, _, _ = loadColdGraphCached(ts) }); got != 1 {
		t.Fatalf("after ClaimIntent: rebuilt %d times, want 1", got)
	}

	// And the cache settles again once writes stop.
	if got := buildDelta(func() { _, _, _ = loadColdGraphCached(ts) }); got != 0 {
		t.Fatalf("settled read rebuilt %d times, want 0", got)
	}
}

// TestGraphOverviewReusesGraphSnapshotWithinUnchangedRound is the end-to-end payoff:
// graphOverviewData reads the whole graph, and the planner calls it every round while
// each worker calls it on every intent claim. Back-to-back calls against an unchanged
// graph must not re-read it — and a write in between must still be picked up.
func TestGraphOverviewReusesGraphSnapshotWithinUnchangedRound(t *testing.T) {
	d := testDB(t)
	expID, err := d.CreateExploration("overview cache probe", "goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	ts := d.Exploration(expID)
	if _, err := ts.AddNode(db.KindFact, map[string]any{"summary": "seed"}, 0, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.AddIntent(map[string]any{"summary": "seed intent"}, 5, nil, "planner"); err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(ts, "planner")

	if got := buildDelta(func() { _ = tools.graphOverviewData() }); got == 0 {
		t.Fatal("first graphOverviewData built nothing; the probe cannot detect a regression")
	}
	if got := buildDelta(func() { _ = tools.graphOverviewData() }); got != 0 {
		t.Fatalf("second graphOverviewData rebuilt the graph %d times, want 0", got)
	}

	// The cache must not hide real progress: a fresh fact has to show up next call.
	if _, err := ts.AddNode(db.KindFact, map[string]any{"summary": "new"}, 0, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}
	if got := buildDelta(func() { _ = tools.graphOverviewData() }); got == 0 {
		t.Fatal("graphOverviewData did not rebuild after a graph write")
	}
}

// TestGraphVersionMovesOnEveryGraphWrite guards the invariant the cache depends on:
// the write paths an exploration exposes all advance GraphVersion. A write path added
// to db/ without a bump would silently serve stale graphs here.
func TestGraphVersionMovesOnEveryGraphWrite(t *testing.T) {
	d := testDB(t)
	expID, err := d.CreateExploration("version probe", "every graph write bumps the version")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	ts := d.Exploration(expID)

	step := func(name string, fn func() error) {
		t.Helper()
		before := ts.GraphVersion()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if after := ts.GraphVersion(); after == before {
			t.Errorf("%s did not advance GraphVersion (still %d)", name, after)
		}
	}

	var factID, intentID, goalID int64
	step("AddNode", func() (err error) {
		factID, err = ts.AddNode(db.KindFact, map[string]any{"summary": "f"}, 0, "confirmed", "worker", nil)
		return err
	})
	step("AddIntent", func() (err error) {
		intentID, err = ts.AddIntent(map[string]any{"summary": "i"}, 5, nil, "planner")
		return err
	})
	// Anchor needs a real asset row (FK on asset_id).
	assets := d.Assets()
	assetID, err := assets.UpsertRootDomain(db.UpsertRootDomainReq{Domain: "cache-probe.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = assets.DeleteByIDs([]int64{assetID}) })
	step("Anchor", func() error { return ts.Anchor(intentID, assetID) })
	step("Link", func() error { return ts.Link(intentID, db.RelYields, factID) })
	step("ClaimIntent", func() error { _, err := ts.ClaimIntent(intentID, "w"); return err })
	step("SetIntentState", func() error { return ts.SetIntentState(intentID, "done") })
	step("SetNodeState", func() error { return ts.SetNodeState(factID, "confirmed") })
	step("CompareAndSetIntentState", func() error {
		_, err := ts.CompareAndSetIntentState(intentID, "done", "open")
		return err
	})
	step("SetIntentBlockedReason", func() error { return ts.SetIntentBlockedReason(intentID, "outage") })
	step("ReopenIntentsByBlockedReason", func() error {
		_, err := ts.ReopenIntentsByBlockedReason("outage")
		return err
	})
	step("ReopenIntent", func() error { _, err := ts.ReopenIntent(intentID); return err })
	step("ResetRunningIntents", func() error { _, err := ts.ResetRunningIntents(); return err })
	step("ReopenBlockedIntents", func() error { _, err := ts.ReopenBlockedIntents(); return err })
	step("AddGoal", func() (err error) {
		goalID, err = ts.AddGoal(map[string]any{"text": "g"}, "planner")
		return err
	})
	step("UpdateGoalPayload", func() error { return ts.UpdateGoalPayload(goalID, "g2", "") })
	step("DeleteGoal", func() error { return ts.DeleteGoal(goalID) })
	step("AddDigest", func() error {
		_, err := ts.AddDigest(map[string]any{"body": "d"}, []int64{factID})
		return err
	})
	step("RecordFinding", func() error {
		_, err := ts.RecordFinding(t.Context(), db.RecordFindingInput{
			ExplorationID: expID, IntentID: intentID, VulnClass: "x", Summary: "s",
		})
		return err
	})
	step("DiscardOpenIntent", func() error {
		id, err := ts.AddIntent(map[string]any{"summary": "doomed"}, 1, nil, "planner")
		if err != nil {
			return err
		}
		return ts.DiscardOpenIntent(id)
	})
	step("SoftDeleteIntent", func() error { _, err := ts.SoftDeleteIntent(intentID, "test"); return err })
	step("CancelIntent", func() error { _, err := ts.CancelIntent(intentID); return err })
}
