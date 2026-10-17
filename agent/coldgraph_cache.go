package agent

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/db"
)

// loadColdGraph reads an exploration's ENTIRE node+edge set (every call passes a
// deliberately-unbounded LIMIT — see the allRows comment in compaction.go). That is
// far more expensive than the capped queries around it, yet within one planner round
// the same exploration is loaded several times: once by the compactor's maintain()
// (compaction.go), once by graphOverviewData (tools.go), and once per directly-related
// source task (tools_digest.go). A worker paying the same cost on every intent claim
// multiplies that by the worker count.
//
// This file memoizes the result. Correctness rests on two things:
//
//  1. The returned *coldGraph and the node map are treated as READ-ONLY by every
//     consumer — coldGraph is only ever built in newColdGraph, and no caller assigns
//     to a *db.Node. A cached value is therefore safe to hand to several goroutines.
//  2. db.ExplorationStore.GraphVersion changes on every write that could alter the
//     snapshot (new/removed nodes, new edges/anchors, any node state transition), so a
//     version match means a previously built snapshot is still current.
type coldgraphEntry struct {
	version uint64
	built   time.Time
	cg      *coldGraph
	byID    map[int64]*db.Node
}

// coldgraphTTL is a backstop against a write path that forgets to bump GraphVersion:
// a snapshot is dropped after this long regardless of version, bounding staleness
// instead of trusting that the bump sites are exhaustive. The cost is one extra full
// load per exploration per window — negligible next to the per-round duplicates this
// cache removes.
const coldgraphTTL = 30 * time.Second

// coldgraphMaxEntries caps retained snapshots (one per live exploration). Oldest-built
// entries are evicted past this, so a long-lived server does not accumulate one full
// graph per task it has ever run.
const coldgraphMaxEntries = 32

var (
	coldgraphMu    sync.RWMutex
	coldgraphByExp = map[int64]*coldgraphEntry{}

	// coldgraphBuilds counts actual full-graph builds (cache misses). Only read by
	// tests, to assert that a hit really avoided the load rather than merely
	// returning equal data.
	coldgraphBuilds atomic.Uint64
)

// loadColdGraphCached is loadColdGraph with per-exploration memoization. The returned
// values MUST NOT be mutated. Falls back to an uncached load on any cache miss.
func loadColdGraphCached(ts *db.ExplorationStore) (*coldGraph, map[int64]*db.Node, error) {
	if ts == nil {
		return nil, nil, errors.New("loadColdGraphCached: nil exploration store")
	}
	expID := ts.ID()
	// Read the version BEFORE the snapshot: a write landing in between bumps the
	// counter, so the entry we are about to store is tagged older than the current
	// version and the next reader rebuilds instead of trusting it.
	version := ts.GraphVersion()

	coldgraphMu.RLock()
	if e := coldgraphByExp[expID]; e != nil && e.version == version {
		fresh := time.Since(e.built) < coldgraphTTL
		if fresh {
			coldgraphMu.RUnlock()
			return e.cg, e.byID, nil
		}
	}
	coldgraphMu.RUnlock()

	cg, byID, err := loadColdGraph(ts)
	if err != nil {
		return nil, nil, err
	}
	coldgraphBuilds.Add(1)

	coldgraphMu.Lock()
	coldgraphByExp[expID] = &coldgraphEntry{version: version, built: time.Now(), cg: cg, byID: byID}
	evictColdgraphLocked()
	coldgraphMu.Unlock()
	return cg, byID, nil
}

// evictColdgraphLocked drops the oldest snapshots once the table is over its cap.
// Callers hold coldgraphMu for writing.
func evictColdgraphLocked() {
	for len(coldgraphByExp) > coldgraphMaxEntries {
		var oldestExp int64
		var oldestAt time.Time
		first := true
		for exp, e := range coldgraphByExp {
			if first || e.built.Before(oldestAt) {
				oldestExp, oldestAt, first = exp, e.built, false
			}
		}
		delete(coldgraphByExp, oldestExp)
	}
}
