// AWS Client VPN SAML ("federated authentication") flow.
//
// A SAML profile has no client cert; the endpoint authenticates the user
// through a browser sign-in at the IdP. The protocol (reverse-engineered
// by the community, see samm-git/aws-vpn-client) rides OpenVPN's CRV1
// challenge/response:
//
//  1. Connect with username "N/A", password "ACS::35001". The server
//     "fails" the auth with AUTH_FAILED,CRV1:R:<sid>::<idp-url>.
//  2. Open <idp-url> in the browser. The IdP is registered with ACS URL
//     http://127.0.0.1:35001/ and POSTs the SAMLResponse there after
//     sign-in; vpnp listens on that port to catch it.
//  3. Reconnect to the SAME server IP (vpnp pins it anyway) with
//     password "CRV1::<sid>::<SAMLResponse>".
//
// The SAML response is several KB, which is why step 3 needs openvpn-aws
// (raised buffers) rather than stock openvpn — see Binary.

package ovpnrun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// samlPort is fixed by AWS: the IdP's ACS URL is registered as
// http://127.0.0.1:35001 when the endpoint is set up for federation.
const samlPort = "35001"

// SAMLAuthPath is the two-line --auth-user-pass file for the SAML flow.
// It briefly holds the one-time CRV1 password; cmdUp removes it once the
// tunnel is up.
func SAMLAuthPath(root string) string { return filepath.Join(RunDir(root), "saml.auth") }

// crv1Pattern matches the challenge inside the AUTH_FAILED control
// message: CRV1:<flags>:<state-id>:<username-b64>:<challenge>, where AWS
// puts the IdP sign-in URL in <challenge>.
var crv1Pattern = regexp.MustCompile(`AUTH_FAILED,CRV1:[^:]*:([^:]+):[^:]*:(https://\S+)`)

// FetchSAMLChallenge runs openvpn once in the foreground — unprivileged,
// auth never succeeds so no tun is created — and harvests the CRV1
// challenge: the session id and the IdP sign-in URL.
func FetchSAMLChallenge(root string, p *Profile, ip string) (sid, url string, err error) {
	bin, err := Binary(true)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(RunDir(root), 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(ConfPath(root), []byte(p.Sanitized), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(SAMLAuthPath(root), []byte("N/A\nACS::"+samlPort+"\n"), 0o600); err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"--config", ConfPath(root),
		"--remote", ip, p.Port, p.Proto,
		"--auth-user-pass", SAMLAuthPath(root),
		"--auth-retry", "none",
		"--verb", "3",
		"--connect-timeout", "20")
	out, _ := cmd.CombinedOutput() // exits non-zero by design (AUTH_FAILED)
	m := crv1Pattern.FindSubmatch(out)
	if m == nil {
		return "", "", fmt.Errorf("no SAML challenge in the openvpn output — is the endpoint reachable and set up for federated auth?\n%s", tail(string(out), 15))
	}
	return string(m[1]), strings.TrimRight(string(m[2]), `'"`), nil
}

// AwaitSAMLResponse serves http://127.0.0.1:35001, opens the IdP URL in
// the default browser, and returns the base64 SAMLResponse the IdP POSTs
// back after the user signs in.
func AwaitSAMLResponse(idpURL string, timeout time.Duration) (string, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:"+samlPort)
	if err != nil {
		return "", fmt.Errorf("cannot listen on 127.0.0.1:%s (the port AWS redirects the sign-in to): %w", samlPort, err)
	}
	got := make(chan string, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := r.PostFormValue("SAMLResponse")
		if resp == "" {
			http.Error(w, "missing SAMLResponse", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<h2>vpnp: signed in</h2><p>You can close this tab and return to the terminal.</p>")
		select {
		case got <- resp:
		default:
		}
	})}
	go srv.Serve(ln) //nolint:errcheck // returns ErrServerClosed on Shutdown
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx) //nolint:errcheck
	}()
	if err := exec.Command("open", idpURL).Run(); err != nil {
		fmt.Println("  could not open the browser automatically — sign in here:")
		fmt.Println("  " + idpURL)
	}
	select {
	case resp := <-got:
		return resp, nil
	case <-time.After(timeout):
		return "", errors.New("timed out waiting for the SAML sign-in — rerun: vpnp up")
	}
}

// WriteSAMLAuth writes the second-stage auth file: the CRV1 response
// carrying the SAML assertion as the password.
func WriteSAMLAuth(root, sid, samlResponse string) (string, error) {
	path := SAMLAuthPath(root)
	body := "N/A\nCRV1::" + sid + "::" + samlResponse + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
