package db

import "database/sql"

// UntouchedSurface is the "did we stop looking while there was still surface" state,
// surfaced to the planner so it is something the run must act on rather than something
// nobody can see.
//
// Why this exists: the planner already has list_untested_assets, but that view is bounded
// by the task's SCOPE predicate — and the scope predicate is routinely wrong (see
// TaskScopeGap). Measured on OWASP Juice Shop, the scope matched 1 of the 41 assets the
// task had discovered, so the one tool that could have shown the planner its remaining
// work showed it essentially nothing. The run then declared itself finished with 15
// discovered assets never touched and a third of its time budget unspent.
//
// So this view is keyed on the task's OWN ownership (task_asset_links), not on scope:
// assets this run discovered and took ownership of, and then never worked on at all.
//
// Untouched counts only assets that are ALSO not claimed by a live (open/running) intent,
// so it answers the gate's question — "is anything being left unattended right now?" — and
// not the outcome row's — "of what we discovered, how much did we ever actually work on?".
// Those are different moments: at outcome time the run is over and nothing is in flight,
// so the two figures legitimately differ.
type UntouchedSurface struct {
	Untouched     int             `json:"untouched"`      // 已发现、从未触碰、且没有在飞意图认领的资产数
	Sample        []CoverageAsset `json:"sample"`         // 上述资产样本（最多 limit 条）
	BudgetSeconds int64           `json:"budget_seconds"` // 任务时间预算；0=不限
	// BudgetLeftPct is the unspent share of the budget; nil when unlimited.
	BudgetLeftPct *float64 `json:"budget_left_pct"`
}

// touchedCTE is the shared definition of "this run worked on that asset": it carries a
// fact OR a finding anchor. Deliberately broader than a fact anchor alone — an asset that
// produced a finding was plainly worked on, even if the run recorded no separate fact for
// it (measured: 2 of 41 assets on the Juice Shop run).
const touchedCTE = `touched AS (
  SELECT DISTINCT ea.asset_id
  FROM exploration_anchors ea
  JOIN exploration_nodes n ON n.id = ea.node_id
  WHERE n.exploration_id = $1 AND n.kind IN ('fact','finding')
)`

// claimedCTE is the alignment fix. The planner de-duplicates by INTENT, and add_intent
// anchors the assets a direction is aimed at — so an asset under an open or running intent
// is already spoken for in the planner's head. The asset-level metric knew nothing about
// that, so the two disagreed, and the disagreement was not free: on the Juice Shop re-run
// the wrap-up gate fired three times over 13 assets the planner had explicitly described
// as "already covered by open intents", and the run burned the remainder of its budget
// re-chewing the same surface for no additional recall.
//
// An asset that a live intent is aimed at is NOT unattended. It is in flight. Only an
// asset that nobody has worked on and nobody is heading for is genuinely left on the table.
const claimedCTE = `claimed AS (
  SELECT DISTINCT ea.asset_id
  FROM exploration_anchors ea
  JOIN exploration_nodes n ON n.id = ea.node_id
  WHERE n.exploration_id = $1 AND n.kind = 'intent' AND n.state IN ('open','running')
)`

// UntouchedSurface returns the discovery-vs-work gap for this exploration's task. The
// task is resolved through tasks.exploration_id, so callers that hold only an
// ExplorationStore (the agent ToolSet) can reach it.
func (s *ExplorationStore) UntouchedSurface(limit int) (*UntouchedSurface, error) {
	if limit <= 0 {
		limit = 15
	}
	out := &UntouchedSurface{Sample: []CoverageAsset{}}
	var usedSeconds int64
	err := s.db.QueryRow(`
WITH task AS (
  SELECT id, COALESCE(first_run_at, created_at) AS start_at,
         COALESCE(completed_at, now()) AS end_at, COALESCE(timeout_seconds, 0) AS budget
  FROM tasks WHERE exploration_id = $1 AND deleted_at IS NULL ORDER BY id LIMIT 1
),
linked AS (SELECT l.asset_id FROM task_asset_links l JOIN task t ON t.id = l.task_id),
`+touchedCTE+`,
`+claimedCTE+`
SELECT COALESCE((SELECT budget FROM task), 0),
       COALESCE((SELECT EXTRACT(EPOCH FROM (end_at - start_at))::bigint FROM task), 0),
       (SELECT count(*) FROM linked l
         WHERE NOT EXISTS (SELECT 1 FROM touched t WHERE t.asset_id = l.asset_id)
           AND NOT EXISTS (SELECT 1 FROM claimed c WHERE c.asset_id = l.asset_id))`,
		s.expID).Scan(&out.BudgetSeconds, &usedSeconds, &out.Untouched)
	if err != nil {
		return nil, err
	}
	if out.BudgetSeconds > 0 {
		left := float64(out.BudgetSeconds-usedSeconds) / float64(out.BudgetSeconds)
		if left < 0 {
			left = 0
		}
		if left > 1 {
			left = 1
		}
		out.BudgetLeftPct = &left
	}
	if out.Untouched == 0 {
		return out, nil
	}
	rows, err := s.db.Query(`
WITH task AS (
  SELECT id FROM tasks WHERE exploration_id = $1 AND deleted_at IS NULL ORDER BY id LIMIT 1
),
linked AS (SELECT l.asset_id FROM task_asset_links l JOIN task t ON t.id = l.task_id),
`+touchedCTE+`,
`+claimedCTE+`
SELECT a.id, a.type, COALESCE(a.url, a.domain, a.ip, a.app_name, a.root_domain, '')
FROM linked l
JOIN assets a ON a.id = l.asset_id
WHERE NOT EXISTS (SELECT 1 FROM touched t WHERE t.asset_id = l.asset_id)
  AND NOT EXISTS (SELECT 1 FROM claimed c WHERE c.asset_id = l.asset_id)
ORDER BY a.id LIMIT $2`, s.expID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a CoverageAsset
		if err := rows.Scan(&a.ID, &a.Type, &a.Label); err != nil {
			return nil, err
		}
		out.Sample = append(out.Sample, a)
	}
	return out, rows.Err()
}

// SurfaceWaiver returns the reason the planner recorded for leaving the remaining
// discovered surface alone, or "" when it has recorded none.
//
// The point is not to force coverage — plenty of goals are legitimately narrow. The point
// is to force a DECISION: "I am finished, and I am choosing not to test these" is a
// perfectly good outcome, but it has to be said out loud rather than arrived at by
// default, because the default is indistinguishable from never having noticed.
func (s *ExplorationStore) SurfaceWaiver() (string, error) {
	var reason sql.NullString
	err := s.db.QueryRow(`SELECT surface_waived_reason FROM explorations WHERE id=$1`, s.expID).Scan(&reason)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return reason.String, nil
}

// SetSurfaceWaiver records (or clears, with an empty reason) the planner's decision to
// stop with discovered surface still untouched.
func (s *ExplorationStore) SetSurfaceWaiver(reason string) error {
	_, err := s.db.Exec(`UPDATE explorations
SET surface_waived_reason = NULLIF($2, ''), surface_waived_at = now(), updated_at = now()
WHERE id = $1`, s.expID, reason)
	return err
}
