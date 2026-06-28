package parity

import "testing"

func TestCorpusNonEmptyAndPinned(t *testing.T) {
	c := Corpus()
	if len(c) == 0 {
		t.Fatal("corpus is empty")
	}
	for _, e := range c {
		if e.Name == "" || e.Language == "" || e.Repo == "" || e.Ref == "" {
			t.Errorf("corpus entry under-specified: %+v", e)
		}
		if len(e.Comparators) == 0 {
			t.Errorf("corpus entry %q lists no comparators", e.Name)
		}
		for _, comp := range e.Comparators {
			if _, ok := ComparatorByName(comp); !ok {
				t.Errorf("corpus entry %q references unknown comparator %q", e.Name, comp)
			}
		}
	}
}

func TestComparatorsPinned(t *testing.T) {
	for _, c := range Comparators() {
		if c.Name == "" || c.Binary == "" || c.PinnedVersion == "" {
			t.Errorf("comparator under-specified: %+v", c)
		}
		if len(c.JSONArgs) == 0 {
			t.Errorf("comparator %q has no JSON args", c.Name)
		}
	}
}

func TestComparatorByName(t *testing.T) {
	if _, ok := ComparatorByName(ToolGrype); !ok {
		t.Error("grype should be a known comparator")
	}
	if _, ok := ComparatorByName("nope"); ok {
		t.Error("unknown comparator should not resolve")
	}
}

func TestAvailableForMissingBinary(t *testing.T) {
	if Available("definitely-not-a-real-binary-xyz123") {
		t.Error("a nonexistent binary must not be reported available")
	}
}

func TestCorpusCoversKnownKEV(t *testing.T) {
	// The corpus must include a known-KEV (Log4Shell-era) entry that declares its
	// KEV oracle so the harness can assert the KEV flag + top risk tier empirically
	// (not merely assert that some JVM entry exists).
	found := false
	for _, e := range Corpus() {
		if e.KnownKEVID != "" {
			found = true
		}
	}
	if !found {
		t.Error("corpus must include an entry with a KnownKEVID oracle (Log4Shell-era)")
	}
}
