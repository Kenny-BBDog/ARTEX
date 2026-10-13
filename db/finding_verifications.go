package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// VerifierAgentKey is the built-in agent that independently reproduces a reported
// finding before it is allowed to count as confirmed.
const VerifierAgentKey = "verifier"

// Verification verdicts (finding_verifications.verdict). Deliberately a distinct
// vocabulary from finding_retests.verdict: those describe re-testing a fix
// (reproduced/fixed/inconclusive), which is a different question from "was this
// fresh report ever real". Reusing `fixed` here would be meaningless.
const (
	VerdictConfirmed    = "confirmed"    // 独立复现成功
	VerdictUnverified   = "unverified"   // 尝试复现但未成功
	VerdictInconclusive = "inconclusive" // 无法判定（受阻塞、证据不足）
)

// ValidVerificationVerdict reports whether v is a known verdict. The empty string is
// not accepted: a verification record must say what it concluded.
func ValidVerificationVerdict(v string) bool {
	switch v {
	case VerdictConfirmed, VerdictUnverified, VerdictInconclusive:
		return true
	}
	return false
}

// FindingVerification is one verification attempt and what it concluded.
type FindingVerification struct {
	ID             int64     `json:"id"`
	FindingID      int64     `json:"finding_id"`
	Verdict        string    `json:"verdict"`
	Summary        string    `json:"summary"`
	Evidence       string    `json:"evidence"`
	Agent          string    `json:"agent"`
	ConversationID *int64    `json:"conversation_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// RecordFindingVerification appends one verification record for findingID and, when
// the verdict is VerdictConfirmed, promotes the finding from FindingCandidate to
// FindingConfirmed in the same transaction (through SetFindingStatusTx, so status
// -change notifications fire exactly as they do for a human triage edit).
//
// Only a `candidate` is promoted. If a human has already triaged the finding into any
// other state (false_positive, ignored, …), their decision stands — the verification is
// still recorded, it just does not overwrite a deliberate judgement. Likewise, only
// `confirmed` ever writes a status: an `unverified` or `inconclusive` verdict leaves the
// finding as a candidate rather than asserting "false positive", which is a triage call
// the system should not be making on its own.
func (d *DB) RecordFindingVerification(ctx context.Context, findingID int64, verdict, summary, evidence, agent string, conversationID *int64) error {
	if findingID <= 0 {
		return errors.New("finding_id 必填")
	}
	if !ValidVerificationVerdict(verdict) {
		return fmt.Errorf("verdict 需为 %s / %s / %s", VerdictConfirmed, VerdictUnverified, VerdictInconclusive)
	}
	summary = strings.TrimSpace(summary)
	evidence = strings.TrimSpace(evidence)
	if summary == "" || evidence == "" {
		return errors.New("summary 与 evidence 必填：无法确认时请写明已检查的内容与阻塞原因")
	}

	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var current string
	err = tx.QueryRowContext(ctx, `SELECT status FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("漏洞 #%d 不存在", findingID)
	}
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_verifications(finding_id, verdict, summary, evidence, agent, conversation_id)
VALUES($1,$2,$3,$4,$5,$6)`, findingID, verdict, summary, evidence, agent, conversationID); err != nil {
		return err
	}

	if verdict == VerdictConfirmed && current == FindingCandidate {
		if _, _, _, _, err := SetFindingStatusTx(ctx, tx, findingID, FindingConfirmed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FindingVerifications returns a finding's verification history, newest first.
func (d *DB) FindingVerifications(findingID int64) ([]*FindingVerification, error) {
	rows, err := d.Query(`SELECT id, finding_id, verdict, summary, evidence, agent, conversation_id, created_at
FROM finding_verifications WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FindingVerification{}
	for rows.Next() {
		v := &FindingVerification{}
		if err := rows.Scan(&v.ID, &v.FindingID, &v.Verdict, &v.Summary, &v.Evidence, &v.Agent, &v.ConversationID, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// CandidateFindings lists findings still awaiting verification, newest first — the
// worklist the verifier agent reads to find what it was triggered for.
func (d *DB) CandidateFindings(limit int) ([]*DBFinding, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := d.Query(`SELECT `+findingSelectCols+`
FROM findings f LEFT JOIN tasks t ON t.id = f.task_id
WHERE f.status=$1 ORDER BY f.id DESC LIMIT $2`, FindingCandidate, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// VerificationEnabled reports whether an enabled verifier agent exists. prove_goal
// consults this to decide whether a candidate finding is a hard blocker: with no
// verifier configured nothing would ever promote a candidate, so refusing candidates
// would deadlock every finding-based goal. Returns false on any lookup failure, which
// the caller reads as "not enabled".
func (d *DB) VerificationEnabled() (bool, error) {
	a, err := d.GetAgentByKey(VerifierAgentKey)
	if err != nil {
		return false, err
	}
	return a != nil && a.Enabled, nil
}

// FindingStatusByNodeID returns the triage status of the finding attached to an
// exploration node, or "" when the node has no findings row (a finding node created
// outside report_finding — tests and legacy fixtures).
func (s *ExplorationStore) FindingStatusByNodeID(nodeID int64) (string, error) {
	var status string
	err := s.db.QueryRow(`SELECT status FROM findings WHERE node_id=$1`, nodeID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return status, err
}

// VerificationEnabled forwards to DB.VerificationEnabled for callers that only hold
// an exploration store.
func (s *ExplorationStore) VerificationEnabled() (bool, error) {
	enabled, err := s.db.VerificationEnabled()
	if err != nil {
		// Treat an unreadable setting as "no verifier": that is the conservative choice
		// for prove_goal, which must not strand a task on a transient DB error.
		return false, nil
	}
	return enabled, nil
}
