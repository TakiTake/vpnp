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

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "up":
		err = cmdUp(os.Args[2:])
	case "down":
		err = cmdDown()
	case "status":
		err = cmdStatus()
	case "dns":
		err = cmdDNS()
	case "logs":
		err = cmdLogs()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`vpnp — AWS Client VPN (split-tunnel) in one command

  vpnp up [-ovpn path]   connect the VPN (asks for your sudo password)
  vpnp down              disconnect and remove the split-DNS entries
  vpnp status            tunnel / routes / split-DNS health
  vpnp dns               edit which DNS suffixes resolve through the VPN
  vpnp logs              follow the openvpn log

While up, the OS routes the VPN's pushed ranges through the tunnel and
everything else directly — every tool just works, no proxy config.
Reconnects are automatic and silent (certificate auth — no browser).
`)
}

// ---------------------------------------------------------------- commands

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	ovpn := fs.String("ovpn", "config/vpn.ovpn", "path to AWS Client VPN config")
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

	fmt.Println("  (openvpn needs root for the utun and routes — sudo may ask for your password)")
	if err := ovpnrun.Start(root, prof, ip); err != nil {
		return err
	}
	if err := ovpnrun.WaitConnected(root, 60*time.Second); err != nil {
		if _, alive := ovpnrun.Pid(root); alive {
			return fmt.Errorf("%w\n(openvpn is still running — clean up with: vpnp down)", err)
		}
		return err
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

	// Let apple/container guests reach the VPN too: their packets are
	// forwarded into the tunnel with the container source IP, which the
	// VPN drops — source-NAT them to the tunnel address.
	subnet := dotEnv(root)["CONTAINER_NAT_SUBNET"]
	if subnet == "" {
		subnet = pfnat.DefaultSubnet
	}
	if subnet != "off" && len(routes) > 0 {
		if iface := routeIface(routes[0]); iface == "" {
			fmt.Println("! tunnel route not found — skipping container NAT (containers won't reach the VPN)")
		} else if err := pfnat.Apply(root, iface, subnet, routes); err != nil {
			fmt.Printf("! container NAT failed (%v) — containers won't reach the VPN; the host is unaffected\n", err)
		} else {
			step(fmt.Sprintf("container NAT — %s reaches the VPN via %s", subnet, iface))
		}
	}

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
		fmt.Printf("containers: NAT %s\n", info)
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

func cmdDNS() error {
	root, err := findRepo()
	if err != nil {
		return err
	}
	if err := ensureDNSFile(root); err != nil {
		return err
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	if err := passthrough(editor, macdns.ConfigPath(root)); err != nil {
		return err
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
