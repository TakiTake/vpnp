package macdns

import (
	"os"
	"path/filepath"
	"testing"
)

func writeDNSConfig(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ConfigPath(root), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestParseConfig(t *testing.T) {
	root := writeDNSConfig(t, `# comment
execute-api.ap-northeast-1.amazonaws.com

nameserver=10.0.0.2
corp.internal
#commented.out
`)
	cfg, err := ParseConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"execute-api.ap-northeast-1.amazonaws.com", "corp.internal"}
	if len(cfg.Suffixes) != len(want) {
		t.Fatalf("suffixes = %v, want %v", cfg.Suffixes, want)
	}
	for i := range want {
		if cfg.Suffixes[i] != want[i] {
			t.Errorf("suffix[%d] = %q, want %q", i, cfg.Suffixes[i], want[i])
		}
	}
	if cfg.Nameserver != "10.0.0.2" {
		t.Errorf("nameserver = %q", cfg.Nameserver)
	}
}

func TestParseConfigMissingFile(t *testing.T) {
	cfg, err := ParseConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Suffixes) != 0 || cfg.Nameserver != "" {
		t.Errorf("expected empty config, got %+v", cfg)
	}
}

func TestParseConfigRejectsBadSuffix(t *testing.T) {
	for _, bad := range []string{"foo/bar", "a b", "../etc", "foo..bar", ".hidden", "-x.example"} {
		root := writeDNSConfig(t, bad+"\n")
		if _, err := ParseConfig(root); err == nil {
			t.Errorf("suffix %q: expected error", bad)
		}
	}
}

func TestAppliedRoundTrip(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Applied(root); len(got) != 0 {
		t.Errorf("Applied on fresh root = %v", got)
	}
	list := "/etc/resolver/a.example\n/etc/resolver/b.example\n"
	if err := os.WriteFile(listPath(root), []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Applied(root)
	if len(got) != 2 || got[0] != "/etc/resolver/a.example" || got[1] != "/etc/resolver/b.example" {
		t.Errorf("Applied = %v", got)
	}
}
