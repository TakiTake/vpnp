// vpnp — thin wrapper around stock OpenVPN for AWS Client VPN.
//
// The endpoint is split-tunnel and certificate-authenticated, so a normal
// OpenVPN client is all that's needed: it adds the pushed routes (e.g.
// 10.0.0.0/16) to a utun and the OS routing table does the split. Every
// tool on the Mac reaches VPN-private IPs automatically — no proxy, no
// proxy env, no per-tool config. vpnp adds the two missing pieces:
//
//   - endpoint IP pinning (the profile's remote-random-hostname otherwise
//     breaks DNS resolution for stock openvpn), and
//   - per-domain split-DNS via /etc/resolver/<suffix> files listed in
//     config/vpn.dns, applied on up and removed on down.
//
// Unlike Amazon's AWS VPN Client app, stock openvpn leaves
// net.inet.ip.forwarding and the default route untouched (validated in
// docs/validate-direct-openvpn.sh), so apple/container keeps working.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TakiTake/vpnp/internal/macdns"
	"github.com/TakiTake/vpnp/internal/ovpnrun"
	"github.com/TakiTake/vpnp/internal/pfnat"
)

// repoRoot is baked in at build time: make install passes
// -ldflags "-X main.repoRoot=$(CURDIR)". Falls back to searching upward
// from the working directory.
var repoRoot string

// version is baked in at release-build time:
// -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	// `vpnp <cmd> -h|--help` prints the command's detailed help.
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		if h, ok := commandHelp[cmd]; ok {
			fmt.Print(h)
			return
		}
	}
	var err error
	switch cmd {
	case "up":
		err = cmdUp(args)
	case "down":
		err = cmdDown()
	case "status":
		err = cmdStatus()
	case "dns":
		err = cmdDNS(args)
	case "access":
		err = cmdAccess(args)
	case "logs":
		err = cmdLogs()
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		if len(args) > 0 {
			if h, ok := commandHelp[args[0]]; ok {
				fmt.Print(h)
				return
			}
			fmt.Fprintf(os.Stderr, "no detailed help for %q\n\n", args[0])
			usage()
			os.Exit(2)
		}
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`vpnp — AWS Client VPN (split-tunnel) client for macOS

USAGE
  vpnp <command> [flags]
  vpnp help <command>     detailed help: behavior, files touched, exit codes

COMMANDS
  up [-ovpn <path>]  connect: pin the endpoint IP, start openvpn as root,
                     apply split-DNS (/etc/resolver) and the container policy
  down               disconnect and undo everything 'up' applied; idempotent
  status             health report, one line per subsystem; read-only, no sudo
  dns [-apply]       edit config/vpn.dns ($EDITOR); -apply skips the editor
                     and just validates + re-applies the file
  access [-apply]    edit config/vpn.access ($EDITOR); -apply skips the editor
                     and just validates + re-applies the file
  logs               follow the openvpn log (blocks until interrupted)
  version            print the vpnp version
  help [command]     this overview, or detailed per-command help

HOW IT WORKS
  Split-tunnel: the OS routes only the VPN's pushed ranges (e.g. 10.0.0.0/16)
  through the tunnel, so every tool reaches VPN-private IPs with no proxy and
  no per-tool config. DNS: only the suffixes in config/vpn.dns resolve through
  the VPN. apple/container guests are DEFAULT-DENY into the tunnel; rules in
  config/vpn.access grant destinations. Host networking (ip.forwarding,
  default route, global DNS) is never modified. Reconnects after drops are
  automatic and silent (certificate auth — no browser, no prompts).

FILES (relative to the repo root; discovered from the binary or by walking up)
  config/vpn.ovpn      AWS Client VPN profile, mutual-certificate auth
  config/vpn.dns       split-DNS suffixes            format: vpnp help dns
  config/vpn.access    container->VPN allowlist      format: vpnp help access
  .env                 optional: VPN_TEST_URL, CONTAINER_NAT_SUBNET
  .run/ovpn.log        openvpn log (what 'vpnp logs' follows)

AUTOMATION / NON-INTERACTIVE USE
  - 'up', 'down', and '-apply' run sudo: expect a password prompt on the TTY
    unless sudo credentials are cached or NOPASSWD is configured.
  - 'dns'/'access' WITHOUT -apply open $EDITOR (interactive). Non-interactive
    callers should write the config file directly, then run 'vpnp dns -apply'
    or 'vpnp access -apply'.
  - Exit codes: 0 success; 1 failure ("ERROR: ..." on stderr); 2 usage error.
    'status' exits 0 only when the VPN is connected — use it as a probe.
`)
}

// commandHelp is the detailed per-command help, shown by
// `vpnp help <command>` and `vpnp <command> -h`.
var commandHelp = map[string]string{
	"up": `vpnp up [-ovpn <path>]

Connect the VPN. Steps, in order:
  1. Parse the .ovpn profile (default config/vpn.ovpn), strip its
     remote/remote-random-hostname lines, resolve the endpoint once with a
     random-prefixed DNS label and pin that IP for the whole session.
  2. SAML profiles only (auth-federate): fetch the sign-in challenge, open
     the browser for the IdP sign-in, catch the SAML response on
     127.0.0.1:35001. Needs openvpn-aws: brew install TakiTake/tap/openvpn-aws
  3. Start openvpn as a root daemon (sudo) with log/pidfile under .run/.
     openvpn owns reconnects from here; certificate auth means no prompts,
     SAML sessions reconnect silently until the AWS session duration
     expires (then: vpnp up again).
  4. Wait up to 60s for the tunnel, then read the pushed routes and DNS
     server from the log.
  5. Write /etc/resolver/<suffix> for each suffix in config/vpn.dns
     (created from its .example on first run) and flush the DNS caches.
  6. Load the container policy (source-NAT + default-deny allowlist from
     config/vpn.access) into the pf anchor com.apple/vpnp.

Flags:
  -ovpn <path>   profile to use (default config/vpn.ovpn); switching
                 endpoints = vpnp down && vpnp up -ovpn <other.ovpn>

Requires sudo (interactive password prompt unless cached/NOPASSWD); a SAML
profile additionally requires an interactive browser sign-in.
Exit: 0 connected and configured; 1 any step failed (partial state is
possible — run 'vpnp down' to clean up, 'vpnp logs' to diagnose).
Errors if already up ("openvpn already running").
`,
	"down": `vpnp down

Disconnect and clean up, in order: remove the /etc/resolver entries written
by up, flush the pf anchor and release the pf enable reference, SIGTERM
openvpn (which removes its routes and the utun device).

Idempotent: safe to run when nothing is up (prints "vpnp was not up.") and
after a crash — it removes whatever leftovers exist.

Requires sudo when there is anything to clean up.
Exit: 0 cleaned up (or nothing to do); 1 a cleanup step failed.
`,
	"status": `vpnp status

Read-only health report; no sudo. Lines, in order (some only when relevant):
  vpn:         openvpn running (pid N) | NOT RUNNING
  routes:      <pushed CIDR> via <utunX> | NOT INSTALLED
  split-dns:   applied /etc/resolver suffixes | none applied
  containers:  NAT <subnet> via <utunX> to <routes> — allow <rules> | no NAT
  forwarding:  current net.inet.ip.forwarding value (vpnp never changes it)
  vpn-test:    reachable | UNREACHABLE — plain curl of VPN_TEST_URL from .env

Exit: 0 the VPN is up; 1 it is not (or a check could not run).
Use as a machine probe: vpnp status >/dev/null && echo connected
`,
	"dns": `vpnp dns [-apply]

Maintain config/vpn.dns — which DNS suffixes resolve through the VPN.
Without flags: opens the file in $VISUAL/$EDITOR (interactive), then
validates and, if the VPN is up, re-applies /etc/resolver immediately.
With -apply: skips the editor — validates the file as-is and re-applies.
Non-interactive callers should edit the file directly, then run -apply.

File format (one directive per line, # comments):
  <suffix>            e.g. execute-api.ap-northeast-1.amazonaws.com
                      covers every subdomain; resolved via the VPN's DNS
  nameserver=<ip>     optional override when the endpoint pushes no DNS

Requires sudo only when re-applying (VPN up).
Exit: 0 saved/applied; 1 invalid file or apply failure.
`,
	"access": `vpnp access [-apply]

Maintain config/vpn.access — what apple/container guests may reach THROUGH
the VPN. Containers are DEFAULT-DENY into the tunnel; only matching allow
rules pass. Host traffic and container internet are never filtered.
Without flags: opens the file in $VISUAL/$EDITOR (interactive), then
validates and, if the VPN is up, re-applies the pf rules immediately.
With -apply: skips the editor — validates the file as-is and re-applies.
Non-interactive callers should edit the file directly, then run -apply.

File format (one rule per line, # comments):
  allow <CIDR|IP|any> [port <n>] [proto tcp|udp]
    any        = everything the VPN routes
    port       implies proto tcp unless proto is given
    no port    = all ports and protocols to that destination
Examples:
  allow 10.0.0.0/16 port 443
  allow 10.0.12.34 port 5432
  allow any

Requires sudo only when re-applying (VPN up).
Exit: 0 saved/applied; 1 invalid file or apply failure.
`,
	"logs": `vpnp logs

Follow the openvpn log (tail -f .run/ovpn.log). Blocks until interrupted —
non-interactive callers should read .run/ovpn.log directly instead.
Useful markers: "Initialization Sequence Completed" (connected),
"AUTH_FAILED", "TLS Error", "SIGTERM" (shutdown).
Exit: 0 on interrupt; 1 if no log exists yet.
`,
}

// ---------------------------------------------------------------- commands

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	ovpn := fs.String("ovpn", "config/vpn.ovpn", "path to AWS Client VPN config")
	fs.Usage = func() { fmt.Fprint(os.Stderr, commandHelp["up"]) }
	fs.Parse(args)

	root, err := findRepo()
	if err != nil {
		return err
	}
	ovpnPath := *ovpn
	if !filepath.IsAbs(ovpnPath) {
		ovpnPath = filepath.Join(root, ovpnPath)
	}
	if _, err := os.Stat(ovpnPath); err != nil {
		return fmt.Errorf("VPN config not found: %s\ndownload it from your AWS Client VPN self-service portal (see config/README.md), then rerun: vpnp up", ovpnPath)
	}
	if pid, ok := ovpnrun.Pid(root); ok {
		return fmt.Errorf("openvpn already running (pid %d) — check: vpnp status, or restart: vpnp down && vpnp up", pid)
	}
	if err := ensureDNSFile(root); err != nil {
		return err
	}
	dnsCfg, err := macdns.ParseConfig(root)
	if err != nil {
		return err
	}

	prof, err := ovpnrun.ParseProfile(ovpnPath)
	if err != nil {
		return err
	}
	ip, err := prof.PinIP()
	if err != nil {
		return err
	}
	step(fmt.Sprintf("endpoint %s → pinned %s (%s/%s)", prof.Host, ip, prof.Port, prof.Proto))

	authFile := ""
	if prof.SAML {
		step("SAML federation profile — fetching the sign-in challenge")
		sid, idpURL, err := ovpnrun.FetchSAMLChallenge(root, prof, ip)
		if err != nil {
			return err
		}
		fmt.Println("  opening your browser — sign in with your identity provider")
		saml, err := ovpnrun.AwaitSAMLResponse(idpURL, 5*time.Minute)
		if err != nil {
			return err
		}
		if authFile, err = ovpnrun.WriteSAMLAuth(root, sid, saml); err != nil {
			return err
		}
		step("signed in")
	}

	fmt.Println("  (openvpn needs root for the utun and routes — sudo may ask for your password)")
	if err := ovpnrun.Start(root, prof, ip, authFile); err != nil {
		return err
	}
	if err := ovpnrun.WaitConnected(root, 60*time.Second); err != nil {
		if _, alive := ovpnrun.Pid(root); alive {
			return fmt.Errorf("%w\n(openvpn is still running — clean up with: vpnp down)", err)
		}
		return err
	}
	if authFile != "" {
		os.Remove(authFile) //nolint:errcheck // one-time password, already consumed
	}
	routes := ovpnrun.PushedRoutes(root)
	step(fmt.Sprintf("VPN connected — split-tunnel, OS routes %s via the tunnel", strings.Join(routes, ", ")))

	ns := dnsCfg.Nameserver
	if ns == "" {
		ns, _ = ovpnrun.PushedDNS(root)
	}
	switch {
	case len(dnsCfg.Suffixes) == 0:
		fmt.Println("! no suffixes in config/vpn.dns — VPN-private hostnames won't resolve; add them with: vpnp dns")
	case ns == "":
		fmt.Println("! the endpoint pushed no DNS server and config/vpn.dns has no nameserver= override — skipping split-DNS")
	default:
		if err := macdns.Apply(root, dnsCfg.Suffixes, ns); err != nil {
			return err
		}
		step(fmt.Sprintf("split-DNS → %s for: %s", ns, strings.Join(dnsCfg.Suffixes, ", ")))
	}

	applyContainerPolicy(root, routes)

	fmt.Print(`
Ready. VPN-private IPs and the domains in config/vpn.dns now work in
every tool — nothing to configure. Check any time with: vpnp status
`)
	return nil
}

func cmdDown() error {
	root, err := findRepo()
	if err != nil {
		return err
	}
	os.Remove(ovpnrun.SAMLAuthPath(root)) //nolint:errcheck // leftover from an aborted SAML sign-in, if any
	pid, running := ovpnrun.Pid(root)
	if !running && len(macdns.Applied(root)) == 0 && pfnat.Info(root) == "" {
		fmt.Println("vpnp was not up.")
		return nil
	}
	fmt.Println("  (cleanup needs root — sudo may ask for your password)")
	if removed, err := macdns.Remove(root); err != nil {
		return err
	} else if len(removed) > 0 {
		step(fmt.Sprintf("removed %d /etc/resolver entr%s", len(removed), plural(len(removed), "y", "ies")))
	}
	if had := pfnat.Info(root) != ""; had {
		if err := pfnat.Remove(root); err != nil {
			return err
		}
		step("container NAT removed")
	}
	if running {
		if err := ovpnrun.Stop(root, pid); err != nil {
			return err
		}
		step("openvpn stopped — routes and utun removed")
	}
	return nil
}

func cmdStatus() error {
	root, err := findRepo()
	if err != nil {
		return err
	}

	pid, running := ovpnrun.Pid(root)
	if !running {
		fmt.Println("vpn:        NOT RUNNING (start with: vpnp up)")
		if left := macdns.Applied(root); len(left) > 0 {
			fmt.Printf("split-dns:  WARNING — %d stale /etc/resolver entries; clean up with: vpnp down\n", len(left))
		}
		return errors.New("not running")
	}
	fmt.Printf("vpn:        openvpn running (pid %d)\n", pid)

	routes := ovpnrun.PushedRoutes(root)
	if len(routes) == 0 {
		fmt.Println("routes:     none pushed yet (still connecting? check: vpnp logs)")
	}
	for _, r := range routes {
		if iface := routeIface(r); iface != "" {
			fmt.Printf("routes:     %s via %s ✓\n", r, iface)
		} else {
			fmt.Printf("routes:     %s NOT INSTALLED — try: vpnp down && vpnp up\n", r)
		}
	}

	if applied := macdns.Applied(root); len(applied) > 0 {
		var suffixes []string
		for _, f := range applied {
			suffixes = append(suffixes, filepath.Base(f))
		}
		fmt.Printf("split-dns:  %s\n", strings.Join(suffixes, ", "))
	} else {
		fmt.Println("split-dns:  none applied (edit with: vpnp dns)")
	}

	if info := pfnat.Info(root); info != "" {
		fmt.Printf("containers: NAT %s (edit with: vpnp access)\n", info)
	} else {
		fmt.Println("containers: no NAT — apple/container guests can't reach the VPN")
	}

	// The container-breaker invariant this whole project exists for.
	if out, err := exec.Command("sysctl", "-n", "net.inet.ip.forwarding").Output(); err == nil {
		v := strings.TrimSpace(string(out))
		fmt.Printf("forwarding: net.inet.ip.forwarding = %s (openvpn never changes it)\n", v)
	}

	if testURL := dotEnv(root)["VPN_TEST_URL"]; testURL != "" {
		if exec.Command("curl", "-sf", "-m", "8", "-o", "/dev/null", testURL).Run() == nil {
			fmt.Printf("vpn-test:   reachable — no proxy config needed (%s)\n", testURL)
		} else {
			fmt.Printf("vpn-test:   UNREACHABLE (%s) — check: vpnp logs\n", testURL)
		}
	}
	return nil
}

// applyContainerPolicy installs (or reloads) the container→VPN NAT and
// allowlist. Failures are warnings, not errors: the host-side VPN works
// regardless.
func applyContainerPolicy(root string, routes []string) {
	subnet := dotEnv(root)["CONTAINER_NAT_SUBNET"]
	if subnet == "" {
		subnet = pfnat.DefaultSubnet
	}
	if subnet == "off" || len(routes) == 0 {
		return
	}
	iface := routeIface(routes[0])
	if iface == "" {
		fmt.Println("! tunnel route not found — skipping container NAT (containers won't reach the VPN)")
		return
	}
	if err := ensureAccessFile(root); err != nil {
		fmt.Printf("! %v\n", err)
		return
	}
	allows, err := pfnat.ParseAccess(root)
	if err != nil {
		fmt.Printf("! container policy NOT applied (%v) — containers won't reach the VPN; fix with: vpnp access\n", err)
		return
	}
	if err := pfnat.Apply(root, iface, subnet, routes, allows); err != nil {
		fmt.Printf("! container NAT failed (%v) — containers won't reach the VPN; the host is unaffected\n", err)
		return
	}
	switch len(allows) {
	case 0:
		fmt.Printf("! containers BLOCKED from the VPN — no allow rules in config/vpn.access (edit: vpnp access)\n")
	default:
		var parts []string
		for _, a := range allows {
			parts = append(parts, a.String())
		}
		step(fmt.Sprintf("container access via %s — allow %s only (default-deny)", iface, strings.Join(parts, ", ")))
	}
}

func cmdAccess(args []string) error {
	fs := flag.NewFlagSet("access", flag.ExitOnError)
	apply := fs.Bool("apply", false, "skip the editor; validate config/vpn.access as-is and re-apply")
	fs.Usage = func() { fmt.Fprint(os.Stderr, commandHelp["access"]) }
	fs.Parse(args)

	root, err := findRepo()
	if err != nil {
		return err
	}
	if err := ensureAccessFile(root); err != nil {
		return err
	}
	if !*apply {
		if err := passthrough(editorCmd(), pfnat.AccessPath(root)); err != nil {
			return err
		}
	}
	if _, err := pfnat.ParseAccess(root); err != nil {
		return err
	}
	if _, running := ovpnrun.Pid(root); !running {
		fmt.Println("saved — applies on next: vpnp up")
		return nil
	}
	fmt.Println("  (re-applying pf rules — sudo may ask for your password)")
	applyContainerPolicy(root, ovpnrun.PushedRoutes(root))
	return nil
}

func cmdDNS(args []string) error {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	apply := fs.Bool("apply", false, "skip the editor; validate config/vpn.dns as-is and re-apply")
	fs.Usage = func() { fmt.Fprint(os.Stderr, commandHelp["dns"]) }
	fs.Parse(args)

	root, err := findRepo()
	if err != nil {
		return err
	}
	if err := ensureDNSFile(root); err != nil {
		return err
	}
	if !*apply {
		if err := passthrough(editorCmd(), macdns.ConfigPath(root)); err != nil {
			return err
		}
	}
	cfg, err := macdns.ParseConfig(root)
	if err != nil {
		return err
	}

	if _, running := ovpnrun.Pid(root); !running {
		fmt.Println("saved — applies on next: vpnp up")
		return nil
	}
	ns := cfg.Nameserver
	if ns == "" {
		ns, _ = ovpnrun.PushedDNS(root)
	}
	if ns == "" {
		return errors.New("no nameserver to apply (endpoint pushed none; set nameserver= in config/vpn.dns)")
	}
	fmt.Println("  (re-applying /etc/resolver — sudo may ask for your password)")
	if _, err := macdns.Remove(root); err != nil {
		return err
	}
	if err := macdns.Apply(root, cfg.Suffixes, ns); err != nil {
		return err
	}
	step(fmt.Sprintf("split-DNS → %s for: %s", ns, strings.Join(cfg.Suffixes, ", ")))
	return nil
}

func cmdLogs() error {
	root, err := findRepo()
	if err != nil {
		return err
	}
	logPath := ovpnrun.LogPath(root)
	if _, err := os.Stat(logPath); err != nil {
		return fmt.Errorf("no openvpn log at %s — start with: vpnp up", logPath)
	}
	return passthrough("tail", "-n", "50", "-f", logPath)
}

// ----------------------------------------------------------------- helpers

func ensureDNSFile(root string) error {
	path := macdns.ConfigPath(root)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	data, err := os.ReadFile(path + ".example")
	if err != nil {
		return fmt.Errorf("missing %s and its .example: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Println("! created config/vpn.dns from the example — put your real VPN DNS")
	fmt.Println("  suffixes in it:  vpnp dns")
	return nil
}

func ensureAccessFile(root string) error {
	path := pfnat.AccessPath(root)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	data, err := os.ReadFile(path + ".example")
	if err != nil {
		return fmt.Errorf("missing %s and its .example: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Println("! created config/vpn.access from the example — containers may reach")
	fmt.Println("  HTTPS in the VPC only; adjust with:  vpnp access")
	return nil
}

// routeIface returns the interface a destination routes through, e.g.
// "utun8", or "" if no route is installed.
func routeIface(dest string) string {
	out, err := exec.Command("route", "-n", "get", "-net", dest).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "interface" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func findRepo() (string, error) {
	marker := filepath.Join("config", "vpn.dns.example")
	if repoRoot != "" {
		if _, err := os.Stat(filepath.Join(repoRoot, marker)); err == nil {
			return repoRoot, nil
		}
	}
	dir, err := os.Getwd()
	if err == nil {
		for {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", errors.New("vpnp repo not found — reinstall with 'make install' or run from inside the repo")
}

func dotEnv(root string) map[string]string {
	m := map[string]string{}
	data, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func editorCmd() string {
	if e := os.Getenv("VISUAL"); e != "" {
		return e
	}
	if e := os.Getenv("EDITOR"); e != "" {
		return e
	}
	return "vi"
}

func passthrough(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func step(msg string) { fmt.Println("✓ " + msg) }
