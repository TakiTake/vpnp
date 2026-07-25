// Package ovpnrun manages a stock OpenVPN process for AWS Client VPN in
// split-tunnel, certificate-auth mode.
//
// It parses the downloaded .ovpn profile, pins the endpoint IP once (the
// profile's remote-random-hostname otherwise makes stock openvpn prepend a
// fresh random DNS label on every attempt, which fails on bare lookups), and
// runs `sudo openvpn --daemon` with a log and pidfile under .run/. OpenVPN
// itself owns the tunnel lifecycle: the profile's ping-restart plus built-in
// reconnect give silent recovery, and certificate auth means no prompts.
package ovpnrun

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Profile is the parsed .ovpn: the remote endpoint plus the profile text
// with the directives we override stripped out.
type Profile struct {
	Host      string
	Port      string
	Proto     string
	Sanitized string
	// SAML is true when the profile carries AWS's `auth-federate`
	// directive: the endpoint authenticates via SAML/SSO federation
	// instead of a client certificate. See saml.go for the flow.
	SAML bool
}

func RunDir(root string) string   { return filepath.Join(root, ".run") }
func ConfPath(root string) string { return filepath.Join(RunDir(root), "ovpn.conf") }
func LogPath(root string) string  { return filepath.Join(RunDir(root), "ovpn.log") }
func PidPath(root string) string  { return filepath.Join(RunDir(root), "ovpn.pid") }

// Binary returns the openvpn executable to use.
//
// SAML profiles need openvpn-aws — stock openvpn caps a TLS control
// message at 2 KB (TLS_CHANNEL_BUF_SIZE) and the AWS SAML flow sends the
// multi-KB SAML response as the password inside one such message.
// openvpn-aws is stock OpenVPN with those buffers raised (formula in
// TakiTake/homebrew-tap).
func Binary(saml bool) (string, error) {
	if v := os.Getenv("VPNP_OPENVPN"); v != "" {
		return v, nil
	}
	if saml {
		if _, err := os.Stat("/opt/homebrew/bin/openvpn-aws"); err == nil {
			return "/opt/homebrew/bin/openvpn-aws", nil
		}
		if p, err := exec.LookPath("openvpn-aws"); err == nil {
			return p, nil
		}
		return "", errors.New("this profile uses SAML federation, which needs the patched openvpn — install it: brew install TakiTake/tap/openvpn-aws")
	}
	if _, err := os.Stat("/opt/homebrew/sbin/openvpn"); err == nil {
		return "/opt/homebrew/sbin/openvpn", nil
	}
	if p, err := exec.LookPath("openvpn"); err == nil {
		return p, nil
	}
	return "", errors.New("openvpn not found — install it: brew install openvpn")
}

// ParseProfile reads the .ovpn and splits it into the remote endpoint and a
// sanitized body. `remote` and `remote-random-hostname` are stripped: the
// caller pins the resolved IP via --remote on the command line instead, so
// both TLS stages hit the same VPN node and random-hostname DNS churn is
// avoided. Everything else (certs, remote-cert-tls, verify-x509-name,
// cipher, reneg-sec) is kept verbatim.
func ParseProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &Profile{Port: "443", Proto: "udp"}
	var body []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		switch {
		case len(fields) > 1 && fields[0] == "remote":
			if p.Host == "" {
				p.Host = fields[1]
				if len(fields) > 2 {
					p.Port = fields[2]
				}
				if len(fields) > 3 {
					p.Proto = fields[3]
				}
			}
			continue
		case len(fields) > 0 && fields[0] == "remote-random-hostname":
			continue
		case len(fields) > 1 && fields[0] == "proto":
			p.Proto = fields[1]
			continue // re-passed via --remote; keeping both is harmless but redundant
		case len(fields) > 0 && fields[0] == "auth-federate":
			// AWS-only directive (SAML federation) — stock openvpn
			// exits on it; vpnp drives the SAML flow itself.
			p.SAML = true
			continue
		case len(fields) > 0 && (fields[0] == "auth-user-pass" || fields[0] == "auth-retry"):
			// Credentials are passed via --auth-user-pass on the
			// command line (SAML flow); auth-retry stays "none" so a
			// consumed one-time SAML password can't retry-loop.
			continue
		}
		body = append(body, line)
	}
	if p.Host == "" {
		return nil, fmt.Errorf("no `remote` line in %s — is this an AWS Client VPN profile?", path)
	}
	p.Sanitized = strings.Join(body, "\n")
	return p, nil
}

// PinIP resolves the endpoint once and returns one address to use for the
// whole session. AWS Client VPN names often only resolve with a random
// leading label (that is what remote-random-hostname is for), so try that
// first and fall back to the bare name.
func (p *Profile) PinIP() (string, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		b := make([]byte, 4)
		rand.Read(b) //nolint:errcheck
		name := hex.EncodeToString(b) + "." + p.Host
		if ip, err := lookupOne(name); err == nil {
			return ip, nil
		} else {
			lastErr = err
		}
	}
	if ip, err := lookupOne(p.Host); err == nil {
		return ip, nil
	}
	return "", fmt.Errorf("cannot resolve %s: %w\n(the endpoint DNS name only resolves while a target network is associated — check with your AWS admin)", p.Host, lastErr)
}

func lookupOne(name string) (string, error) {
	addrs, err := net.LookupHost(name)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a, nil
		}
	}
	return "", fmt.Errorf("no IPv4 address for %s", name)
}

// Start writes the sanitized config and launches openvpn as a root daemon.
//
// The logfile is pre-created user-owned: openvpn (as root) would otherwise
// create it 0600 root, and WaitConnected — running as the user — could
// never read it. openvpn truncates the existing file in place, which keeps
// the user ownership. The stale pidfile is removed so Pid never reads a
// previous run (the user owns .run/, so unlinking the root-owned file works).
//
// --dns-updown disable: openvpn 2.7's built-in DNS handling would otherwise
// install the pushed DNS server as the Mac's GLOBAL resolver (all lookups
// through the VPN, broken DNS if openvpn dies uncleanly). vpnp applies
// per-domain split-DNS via /etc/resolver instead — see internal/macdns.
//
// authFile, when non-empty, is a two-line username/password file passed
// via --auth-user-pass with --auth-retry none (the SAML flow's one-time
// CRV1 password; see saml.go).
func Start(root string, p *Profile, ip, authFile string) error {
	bin, err := Binary(p.SAML)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(RunDir(root), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(ConfPath(root), []byte(p.Sanitized), 0o600); err != nil {
		return err
	}
	if err := os.Remove(PidPath(root)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(LogPath(root)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.WriteFile(LogPath(root), nil, 0o644); err != nil {
		return err
	}
	argv := []string{bin,
		"--config", ConfPath(root),
		"--remote", ip, p.Port, p.Proto,
		"--daemon",
		"--log", LogPath(root),
		"--writepid", PidPath(root),
		"--dns-updown", "disable",
		"--verb", "3",
		"--connect-timeout", "20"}
	if authFile != "" {
		argv = append(argv, "--auth-user-pass", authFile, "--auth-retry", "none")
	}
	cmd := exec.Command("sudo", argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("starting openvpn failed: %w", err)
	}
	return nil
}

var failPattern = regexp.MustCompile(`AUTH_FAILED|TLS Error|Cannot resolve host|Exiting due to fatal error|EXITING`)

// WaitConnected polls the openvpn log until the tunnel is up or a fatal
// error appears.
func WaitConnected(root string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(LogPath(root))
		if err == nil {
			log := string(data)
			if strings.Contains(log, "Initialization Sequence Completed") {
				return nil
			}
			if failPattern.MatchString(log) {
				return fmt.Errorf("openvpn failed to connect:\n%s", tail(log, 15))
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the VPN to connect — check: vpnp logs")
}

var dnsPattern = regexp.MustCompile(`dhcp-option DNS (\d+\.\d+\.\d+\.\d+)`)

// PushedDNS extracts the DNS server the endpoint pushed (from the logged
// PUSH_REPLY), if any.
func PushedDNS(root string) (string, bool) {
	data, err := os.ReadFile(LogPath(root))
	if err != nil {
		return "", false
	}
	m := dnsPattern.FindSubmatch(data)
	if m == nil {
		return "", false
	}
	return string(m[1]), true
}

var routePattern = regexp.MustCompile(`route (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)`)

// PushedRoutes extracts the network routes the endpoint pushed, as
// "addr/prefixlen" strings.
func PushedRoutes(root string) []string {
	data, err := os.ReadFile(LogPath(root))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var routes []string
	for _, m := range routePattern.FindAllSubmatch(data, -1) {
		mask := net.IPMask(net.ParseIP(string(m[2])).To4())
		ones, _ := mask.Size()
		r := fmt.Sprintf("%s/%d", m[1], ones)
		if !seen[r] {
			seen[r] = true
			routes = append(routes, r)
		}
	}
	return routes
}

// Pid returns the daemon pid if the pidfile points at a live openvpn
// process (guards against pid reuse).
func Pid(root string) (int, bool) {
	data, err := os.ReadFile(PidPath(root))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil || !strings.Contains(string(out), "openvpn") {
		return 0, false
	}
	return pid, true
}

// Stop SIGTERMs the openvpn daemon (root-owned, so via sudo) and waits for
// it to exit; openvpn removes its routes and the utun on the way down.
func Stop(root string, pid int) error {
	cmd := exec.Command("sudo", "kill", strconv.Itoa(pid))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stopping openvpn (pid %d) failed: %w", pid, err)
	}
	for i := 0; i < 50; i++ {
		if _, alive := Pid(root); !alive {
			os.Remove(PidPath(root)) //nolint:errcheck // root-owned; openvpn usually removes it
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("openvpn (pid %d) did not exit after SIGTERM", pid)
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
