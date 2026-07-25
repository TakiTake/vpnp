package ovpnrun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleProfile = `client
dev tun
proto udp
remote cvpn-endpoint-abc.prod.clientvpn.ap-northeast-1.amazonaws.com 443
remote-random-hostname
resolv-retry infinite
nobind
remote-cert-tls server
cipher AES-256-GCM
verb 3
<ca>
CERTDATA
</ca>
reneg-sec 0
verify-x509-name vpn.example.internal name
`

func writeProfile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vpn.ovpn")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseProfile(t *testing.T) {
	p, err := ParseProfile(writeProfile(t, sampleProfile))
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "cvpn-endpoint-abc.prod.clientvpn.ap-northeast-1.amazonaws.com" {
		t.Errorf("host = %q", p.Host)
	}
	if p.Port != "443" || p.Proto != "udp" {
		t.Errorf("port/proto = %q/%q", p.Port, p.Proto)
	}
	for _, gone := range []string{"remote ", "remote-random-hostname", "proto udp"} {
		if strings.Contains(p.Sanitized, gone) {
			t.Errorf("sanitized profile still contains %q", gone)
		}
	}
	for _, kept := range []string{"remote-cert-tls server", "verify-x509-name vpn.example.internal name", "CERTDATA", "reneg-sec 0"} {
		if !strings.Contains(p.Sanitized, kept) {
			t.Errorf("sanitized profile lost %q", kept)
		}
	}
}

func TestParseProfileNoRemote(t *testing.T) {
	if _, err := ParseProfile(writeProfile(t, "client\ndev tun\n")); err == nil {
		t.Fatal("expected error for profile without remote")
	}
}

func TestParseProfileDefaults(t *testing.T) {
	p, err := ParseProfile(writeProfile(t, "remote vpn.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != "443" || p.Proto != "udp" {
		t.Errorf("defaults: port/proto = %q/%q, want 443/udp", p.Port, p.Proto)
	}
}

func TestLogParsing(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(RunDir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	log := `2026-07-25 10:00:00 PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.255.0.0,dhcp-option DNS 10.0.0.2,ifconfig 10.100.0.34 255.255.255.224'
2026-07-25 10:00:01 Initialization Sequence Completed
`
	if err := os.WriteFile(LogPath(root), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	dns, ok := PushedDNS(root)
	if !ok || dns != "10.0.0.2" {
		t.Errorf("PushedDNS = %q, %v", dns, ok)
	}
	routes := PushedRoutes(root)
	if len(routes) != 1 || routes[0] != "10.0.0.0/16" {
		t.Errorf("PushedRoutes = %v", routes)
	}
}
