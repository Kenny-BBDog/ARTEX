package db

// TaskDepth measures how hard each route was actually pushed before it was closed —
// the layer between "did we reach the surface" (TaskScopeGap, ClaimCoverage) and "was
// the claim true" (finding verification).
//
// It matters because the system has no state for "the worker decided this path is dead".
// A worker that gives up finishes NORMALLY: the intent ends 'done', it writes a fact,
// and nothing anywhere records that it knocked once and walked away. Such a route also
// counts as "reached" in coverage and is not "silent", so every other metric reads it as
// a healthy, fully-explored asset. Shallow work is invisible, and shallow work is the
// main way recall dies.
//
// Two independent records are crossed to make it visible:
//
//	mechanical — how many actions the route took (tool_use activities on the intent)
//	declared   — what the worker stamped on its own conclusion. record_fact's
//	             `confidence` is documented as "手段没穷尽或证据弱（含只探一次）标 inferred，
//	             确已穷尽且直接看到才标 observed", so `observed` is a claim of exhaustion.
//
// The sharp cell is a route that was barely touched, produced no vulnerability, and
// still stamped its conclusion `observed`. Either the route really was finished (on a
// toy target it often is) or the label is decorative — which is why the sample routes
// ride along: the count screens, the sample adjudicates.

// thinRouteAttempts is the action count at or below which a route counts as "barely
// touched". Two covers the shape this is meant to catch — one probe, or a write probe
// followed by a run — without swallowing the small-but-legitimate recon route.
const thinRouteAttempts = 2

// DepthRoute is one route (intent) and how much it actually got.
type DepthRoute struct {
	IntentID int64  `json:"intent_id"`
	State    string `json:"state"`
	Attempts int    `json:"attempts"` // tool_use activities recorded against this intent
	Facts    int    `json:"facts"`    // intent --yields--> fact
	Claims   int    `json:"claims"`   // intent --yields--> finding
	Inferred int    `json:"inferred"` // of those facts, confidence=inferred
	Observed int    `json:"observed"` // of those facts, confidence=observed
}

// TaskDepth is the per-task rollup. Only `done` intents feed the thin/premature figures:
// the other terminal states are not the worker's own verdict on the route — 'exhausted'
// means it ran out of room (the opposite of giving up), 'blocked' is an error, 'stopped'
// is an external kill. Counting those would mix "gave up early" with "was cut off".
type TaskDepth struct {
	RoutesTerminal int `json:"routes_terminal"` // every terminal intent, for context
	RoutesDone     int `json:"routes_done"`     // the subset the worker concluded itself
	RoutesThin     int `json:"routes_thin"`     // done routes with attempts <= thinRouteAttempts
	RoutesYielding int `json:"routes_yielding"` // done routes that yielded a finding

	FactsInferred int `json:"facts_inferred"` // conclusions that admit the means were not exhausted
	FactsObserved int `json:"facts_observed"` // conclusions stamped as directly observed

	// PrematureExhaustion: done, barely touched, produced no finding, yet stamped a fact
	// `observed`. The agent claims it exhausted the means without having spent any.
	PrematureExhaustion int          `json:"premature_exhaustion"`
	ThinRoutes          []DepthRoute `json:"thin_routes"` // the thin done routes, so the count is auditable
}

// TaskDepth computes this exploration's route-depth rollup. Cheap: one grouped scan of
// the exploration's activity, one of its yields edges.
func (s *ExplorationStore) TaskDepth() (*TaskDepth, error) {
	rows, err := s.db.Query(`
SELECT i.id, i.state,
       COALESCE(a.attempts, 0),
       COALESCE(y.facts, 0), COALESCE(y.claims, 0), COALESCE(y.inferred, 0), COALESCE(y.observed, 0)
FROM exploration_nodes i
LEFT JOIN LATERAL (
    SELECT count(*) FILTER (WHERE kind = 'tool_use') AS attempts
    FROM activity WHERE exploration_id = $1 AND node_id = i.id
) a ON true
LEFT JOIN LATERAL (
    SELECT count(*) FILTER (WHERE n.kind = 'fact') AS facts,
           count(*) FILTER (WHERE n.kind = 'finding') AS claims,
           count(*) FILTER (WHERE n.kind = 'fact' AND n.payload->>'confidence' = 'inferred') AS inferred,
           count(*) FILTER (WHERE n.kind = 'fact' AND n.payload->>'confidence' = 'observed') AS observed
    FROM exploration_edges e
    JOIN exploration_nodes n ON n.id = e.dst_id
    WHERE e.exploration_id = $1 AND e.rel = $2 AND e.src_id = i.id
) y ON true
WHERE i.exploration_id = $1 AND i.kind = 'intent'
  AND i.state IN ('done','blocked','exhausted','stopped')
ORDER BY i.id`, s.expID, RelYields)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := &TaskDepth{ThinRoutes: []DepthRoute{}}
	for rows.Next() {
		var r DepthRoute
		if err := rows.Scan(&r.IntentID, &r.State, &r.Attempts,
			&r.Facts, &r.Claims, &r.Inferred, &r.Observed); err != nil {
			return nil, err
		}
		out.RoutesTerminal++
		if r.State != "done" {
			continue // not the worker's own verdict — see the type comment
		}
		out.RoutesDone++
		out.FactsInferred += r.Inferred
		out.FactsObserved += r.Observed
		if r.Claims > 0 {
			out.RoutesYielding++
		}
		if r.Attempts > thinRouteAttempts {
			continue
		}
		out.RoutesThin++
		out.ThinRoutes = append(out.ThinRoutes, r)
		if r.Claims == 0 && r.Observed > 0 {
			out.PrematureExhaustion++
		}
	}
	return out, rows.Err()
}
