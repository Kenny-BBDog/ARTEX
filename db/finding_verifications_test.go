package db

import (
	"context"
	"testing"
)

// verificationDB creates one candidate finding (AddFinding now starts findings in
// FindingCandidate) and returns the handle plus its id.
func verificationDB(t *testing.T) (*DB, int64) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	fid, err := d.AddFinding(0, 0, "verify-test", "测试漏洞", "high", "original summary", "original evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.DeleteFinding(fid)
		d.Close()
	})
	return d, fid
}

func statusOf(t *testing.T, d *DB, fid int64) string {
	t.Helper()
	f, err := d.GetFinding(fid)
	if err != nil || f == nil {
		t.Fatalf("GetFinding(%d): %v", fid, err)
	}
	return f.Status
}

func TestAddFindingStartsAsCandidate(t *testing.T) {
	d, fid := verificationDB(t)
	if got := statusOf(t, d, fid); got != FindingCandidate {
		t.Fatalf("new finding status = %q, want %q — every machine report must start unverified", got, FindingCandidate)
	}
}

// TestConfirmedVerdictPromotesCandidate is the writeback the whole gate rests on: a
// candidate finding only becomes usable proof once a verification says confirmed.
func TestConfirmedVerdictPromotesCandidate(t *testing.T) {
	d, fid := verificationDB(t)
	ctx := context.Background()

	if err := d.RecordFindingVerification(ctx, fid, VerdictConfirmed, "独立复现成功", "用另一条路径触发，回显一致", "verifier", nil); err != nil {
		t.Fatal(err)
	}
	if got := statusOf(t, d, fid); got != FindingConfirmed {
		t.Fatalf("after confirmed verdict: status = %q, want %q", got, FindingConfirmed)
	}

	// The audit trail keeps the attempt.
	vs, err := d.FindingVerifications(fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Verdict != VerdictConfirmed || vs[0].Agent != "verifier" {
		t.Fatalf("verification history = %+v", vs)
	}
}

// TestNonConfirmingVerdictsLeaveCandidate: the system must never assert "false
// positive" on its own. unverified / inconclusive record the attempt but leave the
// finding unverified, so it still cannot be used as proof.
func TestNonConfirmingVerdictsLeaveCandidate(t *testing.T) {
	ctx := context.Background()
	for _, verdict := range []string{VerdictUnverified, VerdictInconclusive} {
		d, fid := verificationDB(t)
		if err := d.RecordFindingVerification(ctx, fid, verdict, "未能复现", "三次尝试都无效果，对照组一致", "verifier", nil); err != nil {
			t.Fatal(err)
		}
		if got := statusOf(t, d, fid); got != FindingCandidate {
			t.Fatalf("%s verdict changed status to %q, want it left as %q", verdict, got, FindingCandidate)
		}
	}
}

// TestConfirmedDoesNotOverrideHumanTriage: a deliberate human decision outranks a late
// verification. The verdict is still recorded for the record.
func TestConfirmedDoesNotOverrideHumanTriage(t *testing.T) {
	d, fid := verificationDB(t)
	ctx := context.Background()
	if _, err := d.SetFindingStatus(fid, FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordFindingVerification(ctx, fid, VerdictConfirmed, "复现成功", "证据", "verifier", nil); err != nil {
		t.Fatal(err)
	}
	if got := statusOf(t, d, fid); got != FindingFalsePositive {
		t.Fatalf("verification overwrote human triage: status = %q, want %q", got, FindingFalsePositive)
	}
	vs, err := d.FindingVerifications(fid)
	if err != nil || len(vs) != 1 {
		t.Fatalf("verdict should still be recorded, got %+v err=%v", vs, err)
	}
}

func TestRecordFindingVerificationValidation(t *testing.T) {
	d, fid := verificationDB(t)
	ctx := context.Background()

	cases := []struct {
		name                       string
		fid                        int64
		verdict, summary, evidence string
	}{
		{"unknown verdict", fid, "looks-fine", "s", "e"},
		{"empty verdict", fid, "", "s", "e"},
		{"missing summary", fid, VerdictConfirmed, "  ", "e"},
		{"missing evidence", fid, VerdictConfirmed, "s", "  "},
		{"missing finding", 0, VerdictConfirmed, "s", "e"},
	}
	for _, tc := range cases {
		if err := d.RecordFindingVerification(ctx, tc.fid, tc.verdict, tc.summary, tc.evidence, "verifier", nil); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
	// A rejected call must not leave a row behind.
	if vs, err := d.FindingVerifications(fid); err != nil || len(vs) != 0 {
		t.Fatalf("validation failures wrote %d rows (err=%v), want 0", len(vs), err)
	}
	if got := statusOf(t, d, fid); got != FindingCandidate {
		t.Fatalf("validation failures changed status to %q", got)
	}
}

func TestCandidateFindingsListsOnlyUnverified(t *testing.T) {
	d, fid := verificationDB(t)
	ctx := context.Background()

	before, err := d.CandidateFindings(100)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, f := range before {
		if f.ID == fid {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("candidate finding %d missing from CandidateFindings", fid)
	}

	if err := d.RecordFindingVerification(ctx, fid, VerdictConfirmed, "s", "e", "verifier", nil); err != nil {
		t.Fatal(err)
	}
	after, err := d.CandidateFindings(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range after {
		if f.ID == fid {
			t.Fatalf("confirmed finding %d still listed as a candidate", fid)
		}
	}
}

func TestValidVerificationVerdict(t *testing.T) {
	for _, v := range []string{VerdictConfirmed, VerdictUnverified, VerdictInconclusive} {
		if !ValidVerificationVerdict(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	// 'fixed' belongs to the retest vocabulary, not this one.
	for _, v := range []string{"", "fixed", "reproduced", "yes"} {
		if ValidVerificationVerdict(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}
