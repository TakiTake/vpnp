// Package pfnat lets apple/container guests reach VPN destinations —
// governed by an allowlist.
//
// Containers live on the vmnet subnet (192.168.64.0/24 by default). With
// net.inet.ip.forwarding=1 the Mac forwards their packets into the VPN
// tunnel, but with the CONTAINER's source address — and AWS Client VPN
// only accepts traffic sourced from the assigned tunnel IP, so replies
// never come back. The fix is source-NAT on the tunnel interface.
//
// NAT alone would let ANY container reach ANYTHING the VPN routes, so the
// same pf anchor also enforces config/vpn.access: container→VPN traffic
// is filtered INBOUND, before translation, where the source is still the
// container subnet — default-deny, with `allow` rules passing specific
// destinations/ports. Host traffic never matches these rules (the host
// sources VPN traffic from the tunnel IP, not the container subnet), and
// container internet traffic never matches either (only the VPN's pushed
// routes are filtered).
//
// Everything is loaded into the pf anchor "com.apple/vpnp": macOS's stock
// /etc/pf.conf evaluates nat-anchor and anchor "com.apple/*", so no
// system config is modified. pf is enabled reference-counted (pfctl -E)
// and released with the saved token on removal.
package pfnat

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const anchor = "com.apple/vpnp"

// DefaultSubnet is apple/container's vmnet network. Override with
// CONTAINER_NAT_SUBNET in .env ("off" disables NAT and filtering).
const DefaultSubnet = "192.168.64.0/24"

func infoPath(root string) string  { return filepath.Join(root, ".run", "pfnat.info") }
func tokenPath(root string) string { return filepath.Join(root, ".run", "pf.token") }

// AccessPath is the container→VPN allowlist, edited with `vpnp access`.
func AccessPath(root string) string { return filepath.Join(root, "config", "vpn.access") }

// AccessRule is one parsed `allow` line: Dest is a CIDR, a host IP, or
// "any" (= every VPN-pushed route); Port 0 means all ports.
type AccessRule struct {
	Dest  string
	Port  int
	Proto string // tcp or udp; only set when Port is
}

// String renders the rule for status output, e.g. "10.0.0.0/16:443/tcp".
func (a AccessRule) String() string {
	if a.Port == 0 {
		return a.Dest
	}
	return fmt.Sprintf("%s:%d/%s", a.Dest, a.Port, a.Proto)
}

// ParseAccess reads config/vpn.access. Missing file = no rules =
// containers fully blocked from the VPN. Every token is validated — the
// values end up in a root pfctl ruleset.
//
//	allow <CIDR|IP|any> [port <n>] [proto tcp|udp]
func ParseAccess(root string) ([]AccessRule, error) {
	data, err := os.ReadFile(AccessPath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rules []AccessRule
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		bad := func(msg string) error {
			return fmt.Errorf("config/vpn.access line %d: %s (line: %q)", i+1, msg, line)
		}
		if fields[0] != "allow" {
			return nil, bad("lines must start with 'allow'")
		}
		if len(fields) < 2 {
			return nil, bad("missing destination")
		}
		r := AccessRule{Dest: fields[1]}
		if r.Dest != "any" {
			if _, _, err := net.ParseCIDR(r.Dest); err != nil && net.ParseIP(r.Dest) == nil {
				return nil, bad("destination must be a CIDR, an IP, or 'any'")
			}
		}
		rest := fields[2:]
		for len(rest) > 0 {
			switch {
			case rest[0] == "port" && len(rest) > 1:
				p, err := strconv.Atoi(rest[1])
				if err != nil || p < 1 || p > 65535 {
					return nil, bad("port must be 1-65535")
				}
				r.Port = p
				rest = rest[2:]
			case rest[0] == "proto" && len(rest) > 1:
				if rest[1] != "tcp" && rest[1] != "udp" {
					return nil, bad("proto must be tcp or udp")
				}
				r.Proto = rest[1]
				rest = rest[2:]
			default:
				return nil, bad(fmt.Sprintf("unexpected token %q", rest[0]))
			}
		}
		if r.Port != 0 && r.Proto == "" {
			r.Proto = "tcp"
		}
		if r.Port == 0 && r.Proto != "" {
			return nil, bad("proto requires port")
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// buildRules renders the anchor ruleset: the source-NAT, then pass rules
// for the allowlist, then a default block of container→VPN traffic.
//
// macOS pf requires translation rules before filter rules IN THE FILE,
// but evaluates the stages independently at runtime: the filter sees the
// packet inbound (pre-NAT, container source intact), and pass/block use
// `quick` (first match wins), so allows must precede the block.
func buildRules(iface, subnet string, routes []string, allows []AccessRule) string {
	var b strings.Builder
	for _, r := range routes {
		fmt.Fprintf(&b, "nat on %s inet from %s to %s -> (%s)\n", iface, subnet, r, iface)
	}
	for _, a := range allows {
		dests := []string{a.Dest}
		if a.Dest == "any" {
			dests = routes
		}
		for _, d := range dests {
			if a.Port > 0 {
				fmt.Fprintf(&b, "pass in quick inet proto %s from %s to %s port %d\n", a.Proto, subnet, d, a.Port)
			} else {
				fmt.Fprintf(&b, "pass in quick inet from %s to %s\n", subnet, d)
			}
		}
	}
	for _, r := range routes {
		fmt.Fprintf(&b, "block in quick inet from %s to %s\n", subnet, r)
	}
	return b.String()
}

// Apply loads the ruleset into the anchor (replacing whatever it held, so
// it is also the reload path for `vpnp access`) and makes sure pf is
// enabled. Inputs are validated — they end up in a root pfctl ruleset.
func Apply(root, iface, subnet string, routes []string, allows []AccessRule) error {
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
	rules := buildRules(iface, subnet, routes, allows)

	// The rules go to pfctl via stdin — no shell quoting layer (a %q-quoted
	// "\n" once reached pfctl as a literal backslash-n and broke parsing).
	// sudo reads the password from /dev/tty, so a pipe on stdin is fine.
	load := exec.Command("sudo", "pfctl", "-a", anchor, "-f", "-")
	load.Stdin = strings.NewReader(rules)
	if out, err := load.CombinedOutput(); err != nil {
		return fmt.Errorf("loading pf rules failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	// Enable pf once per session; a second -E would leak an enable
	// reference that Remove's single -X could not release.
	if _, err := os.Stat(tokenPath(root)); os.IsNotExist(err) {
		enable := exec.Command("sudo", "pfctl", "-E")
		out, err := enable.CombinedOutput()
		if err != nil {
			return fmt.Errorf("enabling pf failed: %w\n%s", err, strings.TrimSpace(string(out)))
		}
		if m := regexp.MustCompile(`(?i)token\s*:\s*(\d+)`).FindSubmatch(out); m != nil {
			os.WriteFile(tokenPath(root), m[1], 0o644) //nolint:errcheck
		}
	}

	access := "all blocked"
	if len(allows) > 0 {
		var parts []string
		for _, a := range allows {
			parts = append(parts, a.String())
		}
		access = "allow " + strings.Join(parts, ", ")
	}
	info := fmt.Sprintf("%s via %s to %s — %s", subnet, iface, strings.Join(routes, ", "), access)
	return os.WriteFile(infoPath(root), []byte(info+"\n"), 0o644)
}

// Info returns the human-readable summary of the applied NAT+policy.
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
		return fmt.Errorf("removing pf rules failed: %w", err)
	}
	os.Remove(infoPath(root))  //nolint:errcheck
	os.Remove(tokenPath(root)) //nolint:errcheck
	return nil
}
