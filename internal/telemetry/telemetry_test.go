package telemetry

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnabled(t *testing.T) {
	cases := map[string]bool{"1": true, "true": true, "YES": true, "0": false, "": false, "off": false}
	for v, want := range cases {
		t.Setenv("ANST_DEBUG", v)
		t.Setenv("ANST_TELEMETRY", "")
		if got := Enabled(); got != want {
			t.Errorf("Enabled() with ANST_DEBUG=%q = %v, want %v", v, got, want)
		}
	}
}

func TestSpan_WritesWhenEnabled(t *testing.T) {
	t.Setenv("ANST_DEBUG", "1")
	var buf bytes.Buffer
	old := out
	out = &buf
	defer func() { out = old }()

	Span("scan.total")()

	got := buf.String()
	if !strings.Contains(got, "phase=scan.total") || !strings.Contains(got, "ms=") {
		t.Errorf("Span output = %q, want phase=scan.total with ms=", got)
	}
}

func TestSpan_NoOpWhenDisabled(t *testing.T) {
	t.Setenv("ANST_DEBUG", "")
	t.Setenv("ANST_TELEMETRY", "")
	var buf bytes.Buffer
	old := out
	out = &buf
	defer func() { out = old }()

	Span("scan.total")()

	if buf.Len() != 0 {
		t.Errorf("disabled Span wrote %q, want nothing", buf.String())
	}
}
