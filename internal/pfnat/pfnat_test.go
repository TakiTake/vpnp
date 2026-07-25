package pfnat

import (
	"os"
	"path/filepath"
	"testing"
)

// Apply validates its inputs before any privileged command runs, so the
// rejection paths are testable without root.
func TestApplyRejectsBadInput(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name          string
		iface, subnet string
		routes        []string
	}{
		{"bad subnet", "utun8", "not-a-cidr", []string{"10.0.0.0/16"}},
		{"subnet injection", "utun8", "192.168.64.0/24; rm -rf /", []string{"10.0.0.0/16"}},
		{"bad route", "utun8", "192.168.64.0/24", []string{"10.0.0.0/16\nnat on en0"}},
		{"bad iface", "en0; true", "192.168.64.0/24", []string{"10.0.0.0/16"}},
	}
	for _, c := range cases {
		if err := Apply(root, c.iface, c.subnet, c.routes); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestInfoRoundTrip(t *testing.T) {
	root := t.TempDir()
	if Info(root) != "" {
		t.Error("Info on fresh root should be empty")
	}
	if err := os.MkdirAll(filepath.Join(root, ".run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath(root), []byte("192.168.64.0/24 via utun8 to 10.0.0.0/16\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Info(root); got != "192.168.64.0/24 via utun8 to 10.0.0.0/16" {
		t.Errorf("Info = %q", got)
	}
}
