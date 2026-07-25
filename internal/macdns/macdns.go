// Package macdns applies per-domain split-DNS on macOS via /etc/resolver.
//
// For each suffix in config/vpn.dns it writes /etc/resolver/<suffix>
// pointing at the VPN's DNS server, so only those names are resolved
// through the tunnel; every other lookup stays on the Mac's normal
// resolvers. The written file set is tracked in .run/resolver.list so
// `vpnp down` removes exactly what `vpnp up` created.
package macdns

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const resolverDir = "/etc/resolver"

func listPath(root string) string   { return filepath.Join(root, ".run", "resolver.list") }
func stageDir(root string) string   { return filepath.Join(root, ".run", "resolver") }
func ConfigPath(root string) string { return filepath.Join(root, "config", "vpn.dns") }

// DNSConfig is the parsed config/vpn.dns.
type DNSConfig struct {
	Suffixes   []string
	Nameserver string // optional override; empty = use the VPN-pushed server
}

var validSuffix = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// ParseConfig reads config/vpn.dns: one DNS suffix per line, '#' comments,
// optional "nameserver=<ip>" override. Suffix syntax is validated because
// the names become /etc/resolver filenames written under sudo.
func ParseConfig(root string) (*DNSConfig, error) {
	cfg := &DNSConfig{}
	data, err := os.ReadFile(ConfigPath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "nameserver="); ok {
			cfg.Nameserver = strings.TrimSpace(v)
			continue
		}
		if !validSuffix.MatchString(line) || strings.Contains(line, "..") {
			return nil, fmt.Errorf("config/vpn.dns line %d: %q is not a valid DNS suffix", i+1, line)
		}
		cfg.Suffixes = append(cfg.Suffixes, line)
	}
	return cfg, nil
}

// Apply writes one /etc/resolver/<suffix> file per suffix (staged as the
// user, installed in a single sudo call) and flushes the DNS caches.
func Apply(root string, suffixes []string, nameserver string) error {
	if len(suffixes) == 0 {
		return nil
	}
	stage := stageDir(root)
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf("# managed by vpnp — removed by `vpnp down`\nnameserver %s\ntimeout 5\n", nameserver)
	var installed []string
	for _, s := range suffixes {
		if err := os.WriteFile(filepath.Join(stage, s), []byte(content), 0o644); err != nil {
			return err
		}
		installed = append(installed, filepath.Join(resolverDir, s))
	}
	script := fmt.Sprintf("mkdir -p %q && cp %q/* %q/ && dscacheutil -flushcache && killall -HUP mDNSResponder",
		resolverDir, stage, resolverDir)
	if err := sudoSh(script); err != nil {
		return fmt.Errorf("installing /etc/resolver files failed: %w", err)
	}
	return os.WriteFile(listPath(root), []byte(strings.Join(installed, "\n")+"\n"), 0o644)
}

// Applied returns the resolver files recorded as installed by Apply.
func Applied(root string) []string {
	data, err := os.ReadFile(listPath(root))
	if err != nil {
		return nil
	}
	var files []string
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l != "" {
			files = append(files, l)
		}
	}
	return files
}

// Remove deletes the resolver files recorded by Apply and flushes the DNS
// caches. Returns the removed paths.
func Remove(root string) ([]string, error) {
	files := Applied(root)
	if len(files) == 0 {
		return nil, nil
	}
	quoted := make([]string, len(files))
	for i, f := range files {
		// Defense in depth: only ever rm inside /etc/resolver.
		if !strings.HasPrefix(f, resolverDir+"/") || strings.Contains(f, "..") {
			return nil, fmt.Errorf("refusing to remove %q (outside %s)", f, resolverDir)
		}
		quoted[i] = fmt.Sprintf("%q", f)
	}
	script := fmt.Sprintf("rm -f %s && dscacheutil -flushcache && killall -HUP mDNSResponder",
		strings.Join(quoted, " "))
	if err := sudoSh(script); err != nil {
		return nil, fmt.Errorf("removing /etc/resolver files failed: %w", err)
	}
	os.Remove(listPath(root)) //nolint:errcheck
	return files, nil
}

func sudoSh(script string) error {
	cmd := exec.Command("sudo", "sh", "-c", script)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
