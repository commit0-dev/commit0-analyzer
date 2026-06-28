package advisory

import "testing"

// advWithCVSS builds an Advisory carrying a single scored CVSS v3.1 metric.
func advWithCVSS(base float64) *Advisory {
	return &Advisory{
		ID:   "TEST-0001",
		CVSS: []CVSSMetric{{Version: "3.1", BaseScore: base, Vector: "CVSS:3.1/AV:N/AC:L"}},
	}
}

// TestScore_NotReachableIsZero verifies a proven NOT_REACHABLE verdict scores 0
// regardless of CVSS / EPSS / KEV signal (a proven-safe finding is never risk).
func TestScore_NotReachableIsZero(t *testing.T) {
	adv := advWithCVSS(9.8)
	adv.KEV = &KEVEntry{Listed: true}
	adv.EPSS = &EPSSScore{Probability: 0.99}

	got := Score(adv, ReachabilityNotReachable)
	if got.Score != 0 {
		t.Fatalf("NOT_REACHABLE must score 0, got %v", got.Score)
	}
	if got.Tier != "none" {
		t.Fatalf("NOT_REACHABLE tier must be none, got %q", got.Tier)
	}
}

// TestScore_MonotonicInCVSS verifies that, holding everything else equal, a higher
// CVSS base score never produces a lower risk score.
func TestScore_MonotonicInCVSS(t *testing.T) {
	prev := -1.0
	for _, base := range []float64{1.0, 3.0, 5.0, 7.0, 9.0, 10.0} {
		got := Score(advWithCVSS(base), ReachabilitySymbol)
		if got.Score < prev {
			t.Fatalf("score not monotonic in CVSS: base=%v score=%v < prev=%v", base, got.Score, prev)
		}
		prev = got.Score
	}
}

// TestScore_MonotonicInReachability verifies symbol >= package >= unknown for the
// same advisory, and that all are strictly above 0 (reachable findings carry risk).
func TestScore_MonotonicInReachability(t *testing.T) {
	adv := advWithCVSS(7.0)
	sym := Score(adv, ReachabilitySymbol).Score
	pkg := Score(adv, ReachabilityPackage).Score
	unk := Score(adv, ReachabilityUnknown).Score
	if !(sym >= pkg && pkg >= unk) {
		t.Fatalf("reachability not monotonic: symbol=%v package=%v unknown=%v", sym, pkg, unk)
	}
	if unk <= 0 {
		t.Fatalf("reachable (unknown tier) finding must score > 0, got %v", unk)
	}
}

// TestScore_MonotonicInEPSS verifies that a higher EPSS probability never lowers risk.
func TestScore_MonotonicInEPSS(t *testing.T) {
	prev := -1.0
	for _, p := range []float64{0.0, 0.2, 0.5, 0.8, 1.0} {
		adv := advWithCVSS(5.0)
		adv.EPSS = &EPSSScore{Probability: p}
		got := Score(adv, ReachabilityPackage).Score
		if got < prev {
			t.Fatalf("score not monotonic in EPSS: p=%v score=%v < prev=%v", p, got, prev)
		}
		prev = got
	}
}

// TestScore_KEVDominates verifies a KEV-listed reachable finding outscores the same
// finding without KEV and lands in the top (critical) band.
func TestScore_KEVDominates(t *testing.T) {
	base := advWithCVSS(7.0)
	withoutKEV := Score(base, ReachabilityPackage).Score

	kev := advWithCVSS(7.0)
	kev.KEV = &KEVEntry{Listed: true}
	got := Score(kev, ReachabilityPackage)

	if got.Score <= withoutKEV {
		t.Fatalf("KEV must dominate: kev=%v not greater than non-kev=%v", got.Score, withoutKEV)
	}
	if got.Tier != "critical" {
		t.Fatalf("KEV-listed reachable finding must land in the critical band, got tier=%q score=%v", got.Tier, got.Score)
	}
}

// TestScore_MissingEnrichmentNeverIgnore verifies a reachable finding with no CVSS,
// EPSS, or KEV data still carries a non-trivial risk (missing enrichment never
// lowers a finding to "ignore").
func TestScore_MissingEnrichmentNeverIgnore(t *testing.T) {
	adv := &Advisory{ID: "TEST-NODATA"}
	sym := Score(adv, ReachabilitySymbol)
	if sym.Score <= 0 {
		t.Fatalf("reachable finding with no enrichment must score > 0, got %v", sym.Score)
	}
	if sym.Tier == "none" {
		t.Fatalf("reachable finding must not be tier none, got %q", sym.Tier)
	}
}

// TestScore_Deterministic verifies repeated calls return identical results.
func TestScore_Deterministic(t *testing.T) {
	adv := advWithCVSS(8.1)
	adv.EPSS = &EPSSScore{Probability: 0.42}
	adv.KEV = &KEVEntry{Listed: true}
	adv.CWEs = []string{"CWE-79"}

	a := Score(adv, ReachabilitySymbol)
	b := Score(adv, ReachabilitySymbol)
	if a != b {
		t.Fatalf("Score must be deterministic: %+v != %+v", a, b)
	}
	if a.Rationale == "" {
		t.Fatalf("Score must produce a rationale")
	}
}

// TestBestCVSS verifies the highest scored vector wins and an unscored (v4.0)
// vector is still surfaced when it is the only one present.
func TestBestCVSS(t *testing.T) {
	adv := &Advisory{CVSS: []CVSSMetric{
		{Version: "3.1", BaseScore: 5.0, Vector: "v31"},
		{Version: "3.0", BaseScore: 8.0, Vector: "v30"},
	}}
	vec, score, ok := BestCVSS(adv)
	if !ok || score != 8.0 || vec != "v30" {
		t.Fatalf("BestCVSS should pick highest scored: vec=%q score=%v ok=%v", vec, score, ok)
	}

	v4 := &Advisory{CVSS: []CVSSMetric{{Version: "4.0", BaseScore: 0, Vector: "v40"}}}
	vec, score, ok = BestCVSS(v4)
	if !ok || vec != "v40" {
		t.Fatalf("BestCVSS should surface an unscored v4.0 vector: vec=%q score=%v ok=%v", vec, score, ok)
	}
}
