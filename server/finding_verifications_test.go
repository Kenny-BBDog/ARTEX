package server

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/db"
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
