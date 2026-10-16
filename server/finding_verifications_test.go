package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

// TestHostToolsCoverVerifierBindings is the regression test for a wiring bug that only
// showed up in a live run: seedVerifierAgent wrote the verifier's tools into the `tools`
// catalogue and bound them to the agent, but hostTools() never produced the tool objects.
// Binding a name nothing produces leaves the agent with an uncallable tool — the model
// does not error, it degrades into echoing the tool's name as a shell command
// (`Bash: echo "record_finding_verification(...)"`) and never records a verdict.
//
// The unit tests that existed at the time called findingVerificationTools() directly, so
// they exercised the tool bodies and never the wiring. This test asserts the wiring: every
// name the verifier is bound to must actually be produced by hostTools().
func TestHostToolsCoverVerifierBindings(t *testing.T) {
	dsn := testDSNOrSkip(t)
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { pg.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Server{
		ctx:        ctx,
		m:          &Manager{pg: pg, dir: t.TempDir(), tasks: map[string]*Task{}},
		chatBusy:   map[string]bool{},
		chatCancel: map[string]context.CancelCauseFunc{},
	}

	produced := map[string]bool{}
	tools, _ := s.hostTools()
	for _, tl := range tools {
		produced[tl.Name()] = true
	}

	for _, name := range verifierBoundTools {
		if !produced[name] {
			t.Errorf("verifier is bound to %q but hostTools() does not produce it — "+
				"the agent will never be able to call it", name)
		}
	}
}

// TestVerifierToolNamesAreStable pins the two tools that only the verifier owns. If one is
// renamed, seedVerifierAgent's binding list (and the seeded `tools` rows) must move with it.
func TestVerifierToolNamesAreStable(t *testing.T) {
	s := &Server{m: &Manager{tasks: map[string]*Task{}}}
	got := map[string]bool{}
	for _, tl := range s.findingVerificationTools() {
		got[tl.Name()] = true
	}
	for _, want := range []string{"list_candidate_findings", "record_finding_verification"} {
		if !got[want] {
			t.Errorf("findingVerificationTools() no longer provides %q", want)
		}
	}
	if len(got) != 2 {
		t.Errorf("findingVerificationTools() provides %d tools, want exactly 2: %v", len(got), got)
	}
}

// testDSNOrSkip resolves the test DSN, skipping (not failing) when no test database is
// configured — the same contract as the other server tests.
func testDSNOrSkip(t *testing.T) string {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test postgres not configured")
	}
	return dsn
}

// verifierTestServer builds a Server backed by the test database — the same shape
// TestHostToolsCoverVerifierBindings uses, minus the parts the verification tools never
// touch.
func verifierTestServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	pg, err := db.Open(testDSNOrSkip(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { pg.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Server{
		ctx:        ctx,
		m:          &Manager{pg: pg, dir: t.TempDir(), tasks: map[string]*Task{}},
		chatBusy:   map[string]bool{},
		chatCancel: map[string]context.CancelCauseFunc{},
	}, pg
}

func verifierTool(t *testing.T, s *Server, name string) actool.CoreTool {
	t.Helper()
	for _, tl := range s.findingVerificationTools() {
		if tl.Name() == name {
			return tl
		}
	}
	t.Fatalf("findingVerificationTools() does not provide %q", name)
	return nil
}

// TestFindingIDFromReportOutput pins the parse the whole scope rests on. Two ways to get
// it wrong, both silent: the first line of the result carries the exploration NODE id
// (a different handle, the one update_finding_report takes), and RecordedFinding tags
// FindingID `,string`, so the payload holds the id as a quoted string. Reading either
// wrongly yields 0 and the run quietly loses its binding — which is the bug this whole
// change exists to close.
func TestFindingIDFromReportOutput(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want int64
	}{
		{"real shape", "finding recorded: 41\n{\"finding_id\":\"7\",\"finding_node_id\":\"41\",\"traffic\":null}", 7},
		{"no newline", "finding recorded: 41", 0},
		{"malformed json", "finding recorded: 41\nnot json at all", 0},
		{"unquoted id (tag drift)", "finding recorded: 41\n{\"finding_id\":7}", 0},
		{"empty", "", 0},
	}
	for _, c := range cases {
		if got := findingIDFromReportOutput(c.out); got != c.want {
			t.Errorf("%s: findingIDFromReportOutput = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestVerifierToolsAreScopedToTheTriggeringFinding is the regression test for a
// cross-task mix-up. The trigger fires once per report_finding call, so a run is about
// exactly one finding — but the worklist it was handed was a global newest-first list,
// and the write tool accepted any id from it. With two tasks reporting at once, a run
// started for task A's finding could select task B's, confirm it, and leave A's
// unverified — with A's goal blocked on a finding nobody was going to look at.
func TestVerifierToolsAreScopedToTheTriggeringFinding(t *testing.T) {
	s, pg := verifierTestServer(t)
	ctx := context.Background()

	mine, err := pg.AddFinding(0, 0, "scope-mine", "本次触发的那条", "high", "s", "e", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pg.AddFinding(0, 0, "scope-other", "别的任务的漏洞", "high", "s", "e", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.DeleteFinding(mine)
		_, _ = pg.DeleteFinding(other)
	})

	scoped := intercept.WithTriggerFinding(ctx, mine)
	list := verifierTool(t, s, "list_candidate_findings")
	record := verifierTool(t, s, "record_finding_verification")
	mineRef := fmt.Sprintf(`"finding_id":%d`, mine)
	otherRef := fmt.Sprintf(`"finding_id":%d`, other)

	// Reads: scoped, the worklist must not even offer the other finding.
	res, err := list.Call(scoped, json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("scoped list failed: %s", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), mineRef) {
		t.Errorf("scoped list omitted the bound finding: %s", res.Flatten())
	}
	if strings.Contains(res.Flatten(), otherRef) {
		t.Errorf("scoped list leaked another task's finding: %s", res.Flatten())
	}

	// Reads: asking for a different id is refused, not silently ignored.
	res, _ = list.Call(scoped, json.RawMessage(fmt.Sprintf(`{"finding_id":%d}`, other)), nil)
	if !res.IsError {
		t.Errorf("asking for another finding while scoped returned %q, want an error", res.Flatten())
	}

	// Writes: refused there too. The scope is a property of the run, not something the
	// model can decline to honour.
	res, _ = record.Call(scoped, json.RawMessage(fmt.Sprintf(
		`{"finding_id":%d,"verdict":"confirmed","summary":"s","evidence":"e"}`, other)), nil)
	if !res.IsError {
		t.Errorf("recording a verdict for another finding while scoped returned %q, want an error", res.Flatten())
	}
	if f, _ := pg.GetFinding(other); f != nil && f.Status != db.FindingCandidate {
		t.Errorf("the out-of-scope finding was modified anyway: status = %q", f.Status)
	}

	// The bound one goes through.
	res, _ = record.Call(scoped, json.RawMessage(fmt.Sprintf(
		`{"finding_id":%d,"verdict":"confirmed","summary":"s","evidence":"e"}`, mine)), nil)
	if res.IsError {
		t.Fatalf("recording a verdict for the bound finding failed: %s", res.Flatten())
	}
	if f, _ := pg.GetFinding(mine); f == nil || f.Status != db.FindingConfirmed {
		t.Errorf("bound finding was not promoted to confirmed")
	}

	// Unscoped runs (record_fact triggers, direct chat use) keep the old behaviour: every
	// candidate is visible, because nothing told the run to focus on one.
	res, _ = list.Call(ctx, json.RawMessage(`{}`), nil)
	if res.IsError || !strings.Contains(res.Flatten(), otherRef) {
		t.Errorf("an unscoped run should still offer every candidate: %s", res.Flatten())
	}
}
