package pfnat

import (
	"os"
	"path/filepath"
	"strings"
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
		if err := Apply(root, c.iface, c.subnet, c.routes, nil); err == nil {
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

func writeAccess(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(AccessPath(root), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestParseAccess(t *testing.T) {
	root := writeAccess(t, `# comment
allow 10.0.0.0/16 port 443
allow 10.0.12.34 port 5432 proto tcp
allow 10.0.20.0/24
allow any port 53 proto udp
`)
	rules, err := ParseAccess(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []AccessRule{
		{Dest: "10.0.0.0/16", Port: 443, Proto: "tcp"},
		{Dest: "10.0.12.34", Port: 5432, Proto: "tcp"},
		{Dest: "10.0.20.0/24"},
		{Dest: "any", Port: 53, Proto: "udp"},
	}
	if len(rules) != len(want) {
		t.Fatalf("rules = %+v, want %+v", rules, want)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule[%d] = %+v, want %+v", i, rules[i], want[i])
		}
	}
}

func TestParseAccessMissingFile(t *testing.T) {
	rules, err := ParseAccess(t.TempDir())
	if err != nil || rules != nil {
		t.Errorf("missing file: rules=%v err=%v, want nil/nil", rules, err)
	}
}

func TestParseAccessRejectsBadLines(t *testing.T) {
	for _, bad := range []string{
		"deny 10.0.0.0/16",                  // only allow is a valid verb
		"allow",                             // missing dest
		"allow not-an-ip",                   // bad dest
		"allow 10.0.0.0/16 port 0",          // bad port
		"allow 10.0.0.0/16 port 99999",      // bad port
		"allow 10.0.0.0/16 proto tcp",       // proto without port
		"allow 10.0.0.0/16 port 443 x y",    // trailing garbage
		"allow 10.0.0.0/16 port 443; block", // injection attempt
	} {
		root := writeAccess(t, bad+"\n")
		if _, err := ParseAccess(root); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestBuildRules(t *testing.T) {
	got := buildRules("utun8", "192.168.64.0/24", []string{"10.0.0.0/16"}, []AccessRule{
		{Dest: "10.0.0.0/16", Port: 443, Proto: "tcp"},
		{Dest: "any", Port: 53, Proto: "udp"},
		{Dest: "10.0.20.0/24"},
	})
	want := strings.Join([]string{
		"nat on utun8 inet from 192.168.64.0/24 to 10.0.0.0/16 -> (utun8)",
		"pass in quick inet proto tcp from 192.168.64.0/24 to 10.0.0.0/16 port 443",
		"pass in quick inet proto udp from 192.168.64.0/24 to 10.0.0.0/16 port 53",
		"pass in quick inet from 192.168.64.0/24 to 10.0.20.0/24",
		"block in quick inet from 192.168.64.0/24 to 10.0.0.0/16",
	}, "\n") + "\n"
	if got != want {
		t.Errorf("buildRules:\n got:\n%s want:\n%s", got, want)
	}
}

func TestBuildRulesDefaultDeny(t *testing.T) {
	got := buildRules("utun8", "192.168.64.0/24", []string{"10.0.0.0/16"}, nil)
	if strings.Contains(got, "pass") {
		t.Errorf("no allows should mean no pass rules:\n%s", got)
	}
	if !strings.Contains(got, "block in quick inet from 192.168.64.0/24 to 10.0.0.0/16") {
		t.Errorf("missing default block:\n%s", got)
	}
}
