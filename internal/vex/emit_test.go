package vex

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFormatters_Parse(t *testing.T) {
	cases := []struct {
		spec    string
		want    []string
		wantErr bool
	}{
		{"", nil, false},
		{"openvex", []string{"openvex"}, false},
		{"all", []string{"csaf", "cyclonedx", "openvex"}, false},
		{"openvex,csaf", []string{"csaf", "openvex"}, false},
		{"csaf,openvex", []string{"csaf", "openvex"}, false}, // order-normalised
		{"openvex,openvex", []string{"openvex"}, false},      // de-duped
		{"bogus", nil, true},
		{"openvex,bogus", nil, true},
	}
	for _, tc := range cases {
		fs, err := Formatters(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Formatters(%q): want error", tc.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("Formatters(%q): %v", tc.spec, err)
			continue
		}
		var names []string
		for _, f := range fs {
			names = append(names, f.Name())
		}
		if len(names) != len(tc.want) {
			t.Errorf("Formatters(%q) = %v want %v", tc.spec, names, tc.want)
			continue
		}
		for i := range names {
			if names[i] != tc.want[i] {
				t.Errorf("Formatters(%q) = %v want %v", tc.spec, names, tc.want)
				break
			}
		}
	}
}

func TestWrite_SingleToStdout(t *testing.T) {
	var buf bytes.Buffer
	fs, _ := Formatters("openvex")
	if err := Write(fs, sampleDocument(), "-", &buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected output on stdout")
	}
}

func TestWrite_SingleToFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "vex.json")
	fs, _ := Formatters("cyclonedx")
	if err := Write(fs, sampleDocument(), out, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected file written: %v", err)
	}
}

func TestWrite_AllToDirectory(t *testing.T) {
	dir := t.TempDir()
	fs, _ := Formatters("all")
	if err := Write(fs, sampleDocument(), dir, nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		p := filepath.Join(dir, f.FileName())
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s written: %v", p, err)
		}
	}
}

func TestWrite_MultipleToStdoutErrors(t *testing.T) {
	fs, _ := Formatters("all")
	if err := Write(fs, sampleDocument(), "-", &bytes.Buffer{}); err == nil {
		t.Fatal("want error writing multiple formats to stdout")
	}
}
