// Package pfnat lets apple/container guests reach VPN destinations.
//
// Containers live on the vmnet subnet (192.168.64.0/24 by default). With
// net.inet.ip.forwarding=1 the Mac forwards their packets into the VPN
// tunnel, but with the CONTAINER's source address — and AWS Client VPN
// only accepts traffic sourced from the assigned tunnel IP, so replies
// never come back. The fix is source-NAT on the tunnel interface:
//
//	nat on utun8 inet from 192.168.64.0/24 to 10.0.0.0/16 -> (utun8)
//
// The rule is loaded into the pf anchor "com.apple/vpnp": macOS's stock
// /etc/pf.conf evaluates nat-anchor "com.apple/*", so no system config is
// modified. pf is enabled reference-counted (pfctl -E) and released with
// the saved token on removal.
package pfnat

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const anchor = "com.apple/vpnp"

// DefaultSubnet is apple/container's vmnet network. Override with
// CONTAINER_NAT_SUBNET in .env ("off" disables the NAT entirely).
const DefaultSubnet = "192.168.64.0/24"

func infoPath(root string) string  { return filepath.Join(root, ".run", "pfnat.info") }
func tokenPath(root string) string { return filepath.Join(root, ".run", "pf.token") }

// Apply installs the NAT rules (one per pushed route) into the anchor and
// enables pf. Both the subnet and routes must be valid CIDRs — they are
// interpolated into a root shell command.
func Apply(root, iface, subnet string, routes []string) error {
	if _, _, err := net.ParseCIDR(subnet); err != nil {
		return fmt.Errorf("CONTAINER_NAT_SUBNET %q: %w", subnet, err)
	}
	for _, r := range routes {
		if _, _, err := net.ParseCIDR(r); err != nil {
			return fmt.Errorf("pushed route %q: %w", r, err)
		}
	}
	if !regexp.MustCompile(`^utun\d+$`).MatchString(iface) {
		return fmt.Errorf("unexpected tunnel interface %q", iface)
	}
	var rules strings.Builder
	for _, r := range routes {
		fmt.Fprintf(&rules, "nat on %s inet from %s to %s -> (%s)\n", iface, subnet, r, iface)
	}

	// The rules go to pfctl via stdin — no shell quoting layer (a %q-quoted
	// "\n" once reached pfctl as a literal backslash-n and broke parsing).
	// sudo reads the password from /dev/tty, so a pipe on stdin is fine.
	load := exec.Command("sudo", "pfctl", "-a", anchor, "-f", "-")
	load.Stdin = strings.NewReader(rules.String())
	if out, err := load.CombinedOutput(); err != nil {
		return fmt.Errorf("loading pf NAT rules failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	enable := exec.Command("sudo", "pfctl", "-E")
	out, err := enable.CombinedOutput()
	if err != nil {
		return fmt.Errorf("enabling pf failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	if m := regexp.MustCompile(`(?i)token\s*:\s*(\d+)`).FindSubmatch(out); m != nil {
		os.WriteFile(tokenPath(root), m[1], 0o644) //nolint:errcheck
	}
	info := fmt.Sprintf("%s via %s to %s", subnet, iface, strings.Join(routes, ", "))
	return os.WriteFile(infoPath(root), []byte(info+"\n"), 0o644)
}

// Info returns the human-readable summary of the applied NAT, if any.
func Info(root string) string {
	data, err := os.ReadFile(infoPath(root))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// Remove flushes the anchor and releases the pf enable reference.
func Remove(root string) error {
	if Info(root) == "" {
		return nil
	}
	script := fmt.Sprintf("pfctl -a %q -F all 2>/dev/null", anchor)
	if data, err := os.ReadFile(tokenPath(root)); err == nil {
		if token := strings.TrimSpace(string(data)); regexp.MustCompile(`^\d+$`).MatchString(token) {
			script += fmt.Sprintf("; pfctl -X %s 2>/dev/null", token)
		}
	}
	script += "; true"
	cmd := exec.Command("sudo", "sh", "-c", script)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("removing pf NAT rules failed: %w", err)
	}
	os.Remove(infoPath(root))  //nolint:errcheck
	os.Remove(tokenPath(root)) //nolint:errcheck
	return nil
}
