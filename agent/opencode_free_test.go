package agent

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/transcript"
)

// OpenCode's gateway rejects (403 FreeTierError) any request that doesn't look
// like it came from the OpenCode client. These tests pin the two things we
// control on the wire: the derived session id's shape, and that the three
// identity headers are sent together — and only when the profile asked for them.

func TestOpencodeSessionIDShape(t *testing.T) {
	// "ses_" + 12 hex + 14 free characters: the gateway checks the length exactly,
	// one short or one long is rejected.
	const wantLen = 30

	for _, sid := range []string{"conv-42", "exp3-worker-7", "", strings.Repeat("x", 200)} {
		got := opencodeSessionID(sid)
		if len(got) != wantLen {
			t.Errorf("opencodeSessionID(%q) len = %d, want %d", sid, len(got), wantLen)
		}
		if !strings.HasPrefix(got, "ses_") {
			t.Errorf("opencodeSessionID(%q) = %q, want a ses_ prefix", sid, got)
		}
		hexPart := strings.TrimPrefix(got, "ses_")
		hexPart = hexPart[:12]
		for _, c := range hexPart {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("opencodeSessionID(%q) = %q: %q in the 12-character field is not lowercase hex", sid, got, c)
				break
			}
		}
		for _, c := range strings.TrimPrefix(got, "ses_")[12:] {
			if !strings.ContainsRune(opencodeSessionAlphabet, c) {
				t.Errorf("opencodeSessionID(%q) = %q: %q in the trailing field is outside %q", sid, got, c, opencodeSessionAlphabet)
				break
			}
		}
	}
}

// The rule that actually bit us: hex characters are not sufficient. The gateway
// answers 403 FreeTierError for any 12-hex field whose low 12 bits are below
// 0xfc0, so a derivation that ignores those bits fails only sometimes — roughly
// one request in sixteen, which is exactly the intermittent 403 this pins down.
func TestOpencodeSessionIDLowBitsInAcceptedBand(t *testing.T) {
	for i := 0; i < 500; i++ {
		sid := fmt.Sprintf("conv-%d", i)
		got := opencodeSessionID(sid)
		field, err := strconv.ParseUint(strings.TrimPrefix(got, "ses_")[:12], 16, 64)
		if err != nil {
			t.Fatalf("opencodeSessionID(%q) = %q: hex field does not parse: %v", sid, got, err)
		}
		if low := field & 0xfff; low < opencodeHexFloor {
			t.Fatalf("opencodeSessionID(%q) = %q: low 12 bits %#x < %#x, the gateway rejects this", sid, got, low, opencodeHexFloor)
		}
	}
}

func TestOpencodeSessionIDIsStableAndDistinct(t *testing.T) {
	// Stable within a session (so prompt caching / sticky routing still work) and
	// distinct across sessions (so they don't all share one bucket).
	if opencodeSessionID("conv-42") != opencodeSessionID("conv-42") {
		t.Fatal("opencodeSessionID is not stable for the same session id")
	}
	if opencodeSessionID("conv-42") == opencodeSessionID("conv-43") {
		t.Fatal("opencodeSessionID collides across different session ids")
	}
}

func TestOpencodeFreeHeadersSent(t *testing.T) {
	base := &fakeRT{}
	rt := quotaAwareTransport{base: base, opencodeFree: true}
	ctx := transcript.WithSessionID(context.Background(), "conv-42")
	if _, err := rt.RoundTrip(newReq(ctx)); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	h := base.seen.Header
	if got := h.Get("User-Agent"); !strings.HasPrefix(got, "opencode/") {
		t.Errorf("User-Agent = %q, want an opencode/... client string", got)
	}
	want := opencodeSessionID("conv-42")
	// Both headers, same value: sending only one, or values that differ, is rejected.
	for _, name := range []string{"x-opencode-session", "x-opencode-session-id"} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestOpencodeFreeHeadersSkippedWhenOff(t *testing.T) {
	base := &fakeRT{}
	rt := quotaAwareTransport{base: base} // opt-in only
	ctx := transcript.WithSessionID(context.Background(), "conv-42")
	if _, err := rt.RoundTrip(newReq(ctx)); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	h := base.seen.Header
	for _, name := range []string{"x-opencode-session", "x-opencode-session-id"} {
		if got := h.Get(name); got != "" {
			t.Errorf("%s = %q, want empty when opencodeFree is off", name, got)
		}
	}
	if got := h.Get("User-Agent"); strings.HasPrefix(got, "opencode/") {
		t.Errorf("User-Agent = %q, want the default when opencodeFree is off", got)
	}
}

// The generic session-header feature and the opencode identity headers are
// independent: a profile may set either, both, or neither.
func TestOpencodeFreeCoexistsWithSessionHeaderKey(t *testing.T) {
	base := &fakeRT{}
	rt := quotaAwareTransport{base: base, sessionHeaderKey: "x-session-id", opencodeFree: true}
	ctx := transcript.WithSessionID(context.Background(), "conv-42")
	if _, err := rt.RoundTrip(newReq(ctx)); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	h := base.seen.Header
	if got := h.Get("x-session-id"); got != "conv-42" {
		t.Errorf("x-session-id = %q, want conv-42 (the raw session id, unchanged)", got)
	}
	if got := h.Get("x-opencode-session-id"); got != opencodeSessionID("conv-42") {
		t.Errorf("x-opencode-session-id = %q, want the derived id", got)
	}
}

var _ http.RoundTripper = (*fakeRT)(nil)
