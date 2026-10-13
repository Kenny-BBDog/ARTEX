package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// TaskOutcome is one task's post-run summary: what it cost, what it produced, and how
// much of that production survived verification. It exists so runs can be compared
// against each other (and against a ground-truth scenario list) without re-deriving
// every metric from scratch, and so a change to prompts/skills/tools can be scored.
//
// Column semantics — in particular which source each number came from — are documented
// on the task_outcome table in schema.sql. The one worth repeating: FindingsClaimed is
// everything a worker reported, FindingsConfirmed is what independent verification
// upheld. The gap between them is the point.
type TaskOutcome struct {
	TaskID        int64      `json:"task_id"`
	ExplorationID int64      `json:"exploration_id"`
	Status        string     `json:"status"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	ComputedAt    time.Time  `json:"computed_at"`

	LLMCalls         int64 `json:"llm_calls"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`

	GoalsTotal int `json:"goals_total"`
	GoalsMet   int `json:"goals_met"`

	FindingsClaimed       int `json:"findings_claimed"`
	FindingsConfirmed     int `json:"findings_confirmed"`
	FindingsFalsePositive int `json:"findings_false_positive"`
	FindingsCritical      int `json:"findings_critical"`
	FindingsHigh          int `json:"findings_high"`
	FindingsMedium        int `json:"findings_medium"`
	FindingsLow           int `json:"findings_low"`

	RetestsFixed int `json:"retests_fixed"`

	CoverageDenominator int      `json:"coverage_denominator"`
	CoverageTested      int      `json:"coverage_tested"`
	CoveragePct         *float64 `json:"coverage_pct"`

	// The reached × claimed cross-product (see ClaimCoverage). CoverageTested is the
	// "reached" leg; these add what was *asserted* about those reached assets. The gap
	// between them — SilentAssets — is the signal that makes the agent better rather than
	// merely quieter, so it is stored rather than derived on read.
	ClaimedAssets          int             `json:"claimed_assets"`
	ClaimedConfirmedAssets int             `json:"claimed_confirmed_assets"`
	SilentAssets           int             `json:"silent_assets"`
	SilentAssetList        []CoverageAsset `json:"silent_asset_list"`

	// The gap *upstream* of the cross-product: assets the task owns but its own scope
	// does not cover, so they never entered the denominator at all. UncoveredAgent splits
	// out the ones a worker inserted itself — a scope the agent outgrew, rather than
	// bookkeeping that fell behind. See ScopeGap.
	LinkedAssets         int             `json:"linked_assets"`
	UncoveredAssets      int             `json:"uncovered_assets"`
	UncoveredAgentAssets int             `json:"uncovered_agent_assets"`
	UncoveredAssetList   []ScopeGapAsset `json:"uncovered_asset_list"`

	DurationSeconds int64 `json:"duration_seconds"`
	ToolCalls       int   `json:"tool_calls"`
	ToolErrors      int   `json:"tool_errors"`
	IdleTurns       int   `json:"idle_turns"`
}

// outcomeSelect is the LATERAL aggregation, keyed on one task id. It follows the shape
// established by TaskListMetricsAll (db/exploration.go): one scan of `tasks`, every
// derived metric in its own LEFT JOIN LATERAL, COALESCE so a task with no activity still
// yields a row.
const outcomeSelect = `
SELECT
    task.exploration_id,
    task.status,
    task.completed_at,
    COALESCE(u.calls, 0), COALESCE(u.inp, 0), COALESCE(u.out, 0), COALESCE(u.cr, 0), COALESCE(u.cw, 0),
    COALESCE(g.total, 0), COALESCE(g.met, 0),
    COALESCE(f.total, 0), COALESCE(f.confirmed, 0), COALESCE(f.fp, 0),
    COALESCE(f.crit, 0), COALESCE(f.high, 0), COALESCE(f.med, 0), COALESCE(f.low, 0),
    COALESCE(rt.fixed, 0),
    COALESCE(a.calls, 0), COALESCE(a.errors, 0), COALESCE(a.idle, 0),
    COALESCE(EXTRACT(EPOCH FROM (task.completed_at - COALESCE(task.first_run_at, task.created_at)))::bigint, 0)
FROM tasks task
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS calls, SUM(input_tokens) AS inp, SUM(output_tokens) AS out,
           SUM(cache_read) AS cr, SUM(cache_write) AS cw
    FROM llm_usage WHERE exploration_id = task.exploration_id
) u ON true
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE state = 'met') AS met
    FROM exploration_nodes WHERE exploration_id = task.exploration_id AND kind = 'goal'
) g ON true
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS total,
           COUNT(*) FILTER (WHERE status = 'confirmed') AS confirmed,
           COUNT(*) FILTER (WHERE status = 'false_positive') AS fp,
           COUNT(*) FILTER (WHERE severity = 'critical') AS crit,
           COUNT(*) FILTER (WHERE severity = 'high') AS high,
           COUNT(*) FILTER (WHERE severity = 'medium') AS med,
           COUNT(*) FILTER (WHERE severity = 'low') AS low
    FROM findings WHERE task_id = task.id
) f ON true
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS fixed
    FROM finding_retests ret
    JOIN findings rf ON rf.id = ret.finding_id
    WHERE rf.task_id = task.id AND ret.status = 'completed' AND ret.verdict = 'fixed'
) rt ON true
LEFT JOIN LATERAL (
    SELECT COUNT(*) FILTER (WHERE kind = 'tool_use') AS calls,
           COUNT(*) FILTER (WHERE kind = 'tool_result' AND is_error) AS errors,
           COUNT(*) FILTER (WHERE kind = 'empty_turn') AS idle
    FROM activity WHERE exploration_id = task.exploration_id
) a ON true
WHERE task.id = $1`

// ComputeTaskOutcome aggregates one task's outcome. Returns (nil, nil) when no such task
// exists. Coverage comes from the asset store rather than the SQL above, because the
// scope/coverage CTEs already live there and are not worth duplicating.
//
// Requires llm_usage to exist. That table is created by EnsureLLMUsageTable (embedded DDL,
// not schema.sql) from the server's Manager constructor, which runs before the scheduler —
// so in production it is always there. Callers that open a DB directly must ensure it.
func (d *DB) ComputeTaskOutcome(ctx context.Context, taskID int64) (*TaskOutcome, error) {
	o := &TaskOutcome{TaskID: taskID, ComputedAt: time.Now()}
	var completed sql.NullTime
	err := d.QueryRowContext(ctx, outcomeSelect, taskID).Scan(
		&o.ExplorationID, &o.Status, &completed,
		&o.LLMCalls, &o.InputTokens, &o.OutputTokens, &o.CacheReadTokens, &o.CacheWriteTokens,
		&o.GoalsTotal, &o.GoalsMet,
		&o.FindingsClaimed, &o.FindingsConfirmed, &o.FindingsFalsePositive,
		&o.FindingsCritical, &o.FindingsHigh, &o.FindingsMedium, &o.FindingsLow,
		&o.RetestsFixed,
		&o.ToolCalls, &o.ToolErrors, &o.IdleTurns,
		&o.DurationSeconds,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if completed.Valid {
		t := completed.Time
		o.CompletedAt = &t
	}
	if cov, err := d.Assets().TaskCoverage(taskID, o.ExplorationID); err == nil && cov != nil {
		o.CoverageDenominator, o.CoverageTested, o.CoveragePct = cov.Denominator, cov.Tested, cov.Pct
	}
	// The claim side of the cross-product. Both calls read the same exploration anchors;
	// keeping them separate statements mirrors how coverage already reaches into the asset
	// store rather than duplicating its scope CTE inside the outcome SQL.
	if cc, err := d.Assets().TaskClaimCoverage(taskID, o.ExplorationID, silentAssetSampleLimit); err == nil && cc != nil {
		o.ClaimedAssets, o.ClaimedConfirmedAssets = cc.Claimed, cc.Confirmed
		o.SilentAssets = cc.Silent
		if cc.SilentAssets != nil {
			o.SilentAssetList = cc.SilentAssets
		}
	}
	// The scope gap rides along because it explains the denominator the two blocks above
	// are divided by: an asset outside the scope is not "silent", it is uncountable.
	if sg, err := d.Assets().TaskScopeGap(taskID, o.ExplorationID, silentAssetSampleLimit); err == nil && sg != nil {
		o.LinkedAssets, o.UncoveredAssets, o.UncoveredAgentAssets = sg.Linked, sg.Uncovered, sg.UncoveredAgent
		if sg.UncoveredAssets != nil {
			o.UncoveredAssetList = sg.UncoveredAssets
		}
	}
	return o, nil
}

// silentAssetSampleLimit caps how many silent assets ride along in the outcome row. The
// count is exact; the list is a sample, because its purpose is to seed the next run's
// intents and to let a planner be scored — not to be an exhaustive report.
const silentAssetSampleLimit = 20

// UpsertTaskOutcome writes (or refreshes) one task's outcome row. Idempotent: the sweep
// may recompute the same task more than once as late writes land.
func (d *DB) UpsertTaskOutcome(ctx context.Context, o *TaskOutcome) error {
	if o == nil || o.TaskID <= 0 {
		return errors.New("task_outcome: task_id 必填")
	}
	silentJSON, err := json.Marshal(o.SilentAssetList)
	if err != nil || len(o.SilentAssetList) == 0 {
		silentJSON = []byte("[]")
	}
	uncoveredJSON, err := json.Marshal(o.UncoveredAssetList)
	if err != nil || len(o.UncoveredAssetList) == 0 {
		uncoveredJSON = []byte("[]")
	}
	_, err = d.ExecContext(ctx, `
INSERT INTO task_outcome(
    task_id, exploration_id, status, completed_at, computed_at,
    llm_calls, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
    goals_total, goals_met,
    findings_claimed, findings_confirmed, findings_false_positive,
    findings_critical, findings_high, findings_medium, findings_low,
    retests_fixed, coverage_denominator, coverage_tested, coverage_pct,
    claimed_assets, claimed_confirmed_assets, silent_assets, silent_asset_list,
    linked_assets, uncovered_assets, uncovered_agent_assets, uncovered_asset_list,
    duration_seconds, tool_calls, tool_errors, idle_turns)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,
        $24,$25,$26,$27::jsonb,$28,$29,$30,$31::jsonb,$32,$33,$34,$35)
ON CONFLICT (task_id) DO UPDATE SET
    exploration_id = EXCLUDED.exploration_id, status = EXCLUDED.status,
    completed_at = EXCLUDED.completed_at, computed_at = EXCLUDED.computed_at,
    llm_calls = EXCLUDED.llm_calls, input_tokens = EXCLUDED.input_tokens,
    output_tokens = EXCLUDED.output_tokens, cache_read_tokens = EXCLUDED.cache_read_tokens,
    cache_write_tokens = EXCLUDED.cache_write_tokens,
    goals_total = EXCLUDED.goals_total, goals_met = EXCLUDED.goals_met,
    findings_claimed = EXCLUDED.findings_claimed, findings_confirmed = EXCLUDED.findings_confirmed,
    findings_false_positive = EXCLUDED.findings_false_positive,
    findings_critical = EXCLUDED.findings_critical, findings_high = EXCLUDED.findings_high,
    findings_medium = EXCLUDED.findings_medium, findings_low = EXCLUDED.findings_low,
    retests_fixed = EXCLUDED.retests_fixed,
    coverage_denominator = EXCLUDED.coverage_denominator, coverage_tested = EXCLUDED.coverage_tested,
    coverage_pct = EXCLUDED.coverage_pct,
    claimed_assets = EXCLUDED.claimed_assets,
    claimed_confirmed_assets = EXCLUDED.claimed_confirmed_assets,
    silent_assets = EXCLUDED.silent_assets, silent_asset_list = EXCLUDED.silent_asset_list,
    linked_assets = EXCLUDED.linked_assets, uncovered_assets = EXCLUDED.uncovered_assets,
    uncovered_agent_assets = EXCLUDED.uncovered_agent_assets,
    uncovered_asset_list = EXCLUDED.uncovered_asset_list,
    duration_seconds = EXCLUDED.duration_seconds, tool_calls = EXCLUDED.tool_calls,
    tool_errors = EXCLUDED.tool_errors, idle_turns = EXCLUDED.idle_turns`,
		o.TaskID, o.ExplorationID, o.Status, o.CompletedAt, o.ComputedAt,
		o.LLMCalls, o.InputTokens, o.OutputTokens, o.CacheReadTokens, o.CacheWriteTokens,
		o.GoalsTotal, o.GoalsMet,
		o.FindingsClaimed, o.FindingsConfirmed, o.FindingsFalsePositive,
		o.FindingsCritical, o.FindingsHigh, o.FindingsMedium, o.FindingsLow,
		o.RetestsFixed, o.CoverageDenominator, o.CoverageTested, o.CoveragePct,
		o.ClaimedAssets, o.ClaimedConfirmedAssets, o.SilentAssets, string(silentJSON),
		o.LinkedAssets, o.UncoveredAssets, o.UncoveredAgentAssets, string(uncoveredJSON),
		o.DurationSeconds, o.ToolCalls, o.ToolErrors, o.IdleTurns)
	return err
}

const outcomeCols = `task_id, exploration_id, status, completed_at, computed_at,
    llm_calls, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
    goals_total, goals_met,
    findings_claimed, findings_confirmed, findings_false_positive,
    findings_critical, findings_high, findings_medium, findings_low,
    retests_fixed, coverage_denominator, coverage_tested, coverage_pct,
    claimed_assets, claimed_confirmed_assets, silent_assets, silent_asset_list,
    linked_assets, uncovered_assets, uncovered_agent_assets, uncovered_asset_list,
    duration_seconds, tool_calls, tool_errors, idle_turns`

func scanOutcome(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*TaskOutcome, error) {
	var out []*TaskOutcome
	for rows.Next() {
		o := &TaskOutcome{}
		var completed sql.NullTime
		var silentJSON, uncoveredJSON []byte
		if err := rows.Scan(
			&o.TaskID, &o.ExplorationID, &o.Status, &completed, &o.ComputedAt,
			&o.LLMCalls, &o.InputTokens, &o.OutputTokens, &o.CacheReadTokens, &o.CacheWriteTokens,
			&o.GoalsTotal, &o.GoalsMet,
			&o.FindingsClaimed, &o.FindingsConfirmed, &o.FindingsFalsePositive,
			&o.FindingsCritical, &o.FindingsHigh, &o.FindingsMedium, &o.FindingsLow,
			&o.RetestsFixed, &o.CoverageDenominator, &o.CoverageTested, &o.CoveragePct,
			&o.ClaimedAssets, &o.ClaimedConfirmedAssets, &o.SilentAssets, &silentJSON,
			&o.LinkedAssets, &o.UncoveredAssets, &o.UncoveredAgentAssets, &uncoveredJSON,
			&o.DurationSeconds, &o.ToolCalls, &o.ToolErrors, &o.IdleTurns,
		); err != nil {
			return nil, err
		}
		if completed.Valid {
			t := completed.Time
			o.CompletedAt = &t
		}
		// Always a non-null JSON array in the column, but an older row written before the
		// column existed decodes to nothing — leave the slice nil rather than erroring.
		if len(silentJSON) > 0 {
			_ = json.Unmarshal(silentJSON, &o.SilentAssetList)
		}
		if len(uncoveredJSON) > 0 {
			_ = json.Unmarshal(uncoveredJSON, &o.UncoveredAssetList)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// GetTaskOutcome returns one task's stored outcome, or (nil, nil) when none is computed yet.
func (d *DB) GetTaskOutcome(taskID int64) (*TaskOutcome, error) {
	rows, err := d.Query(`SELECT `+outcomeCols+` FROM task_outcome WHERE task_id=$1`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanOutcome(rows)
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return out[0], nil
}

// ListTaskOutcomes returns outcomes newest-completed first, optionally filtered by task
// status ("" = all). This is the read side of the metrics flywheel: pair it with a
// scenario's known findings to get recall/precision.
func (d *DB) ListTaskOutcomes(status string, limit int) ([]*TaskOutcome, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	// One static statement; `$1 = ''` expresses "no filter" without building SQL.
	rows, err := d.Query(`SELECT `+outcomeCols+`
FROM task_outcome
WHERE ($1 = '' OR status = $1)
ORDER BY completed_at DESC NULLS LAST, task_id DESC
LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanOutcome(rows)
}

// TasksNeedingOutcome lists terminal tasks whose outcome is missing or stale, i.e. it was
// computed before the task finished. Only tasks that have been terminal for at least the
// grace period qualify.
//
// The grace period matters: a task is marked done BEFORE its running workers are
// cancelled (server/engine.go, planner's all-goals-met branch), so they keep writing for
// a short while after. Computing immediately would systematically undercount. Waiting
// also makes this self-healing across restarts — a task that finished while the server
// was down is picked up on the next pass.
func (d *DB) TasksNeedingOutcome(grace time.Duration, limit int) ([]int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	cutoff := time.Now().Add(-grace)
	rows, err := d.Query(`
SELECT task.id
FROM tasks task
LEFT JOIN task_outcome o ON o.task_id = task.id
WHERE task.deleted_at IS NULL
  AND task.status IN ('done','failed','timeout')
  AND task.completed_at IS NOT NULL
  AND task.completed_at < $1
  AND (o.task_id IS NULL OR o.computed_at < task.completed_at)
ORDER BY task.completed_at
LIMIT $2`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
