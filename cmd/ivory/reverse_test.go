//go:build ivory

package main

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/ti"
)

// plainEcho serves plain TCP: each connection gets what it sent, in upper
// case, once the client has closed its side.
func plainEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				b, err := io.ReadAll(c)
				if err != nil {
					return
				}
				c.Write([]byte(strings.ToUpper(string(b))))
			}()
		}
	}()
	return ln.Addr().String()
}

// tlsRoundTrip sends msg over TLS to addr and returns the answer, or the
// handshake error.
func tlsRoundTrip(t *testing.T, addr string, config *tls.Config, msg string) (string, error) {
	t.Helper()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, config)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		return "", err
	}
	c.CloseWrite()
	b, err := io.ReadAll(c)
	return string(b), err
}

func TestReverse(t *testing.T) {
	ca, err := readCertificates(pki + "bp256-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	backend := plainEcho(t)
	addr, stop := startSidecar(t, "reverse", "-json", "-backend", backend, "-client-auth", "require",
		"-ca", pki+"bp256-ca.pem", "-cert", pki+"bp256-server.pem", "-key", pki+"bp256-server.key")

	// A TI client with the Brainpool client identity gets through.
	client := loadPair(t, "bp256-client")
	got, err := tlsRoundTrip(t, addr, ti.ClientConfig(&client, &ti.Verifier{CAs: ca}), "hello backend\n")
	if err != nil || got != "HELLO BACKEND\n" {
		t.Errorf("answer %q, %v", got, err)
	}
	// One whose certificate fails the check, and one without, don't.
	rsa := loadPair(t, "rsa-client")
	if got, err := tlsRoundTrip(t, addr, ti.ClientConfig(&rsa, &ti.Verifier{CAs: ca}), "x"); err == nil && got != "" {
		t.Errorf("untrusted client certificate: answer %q", got)
	}
	if got, err := tlsRoundTrip(t, addr, ti.ClientConfig(nil, &ti.Verifier{CAs: ca}), "x"); err == nil && got != "" {
		t.Errorf("no client certificate: answer %q", got)
	}

	evs := events(t, stop())
	accepts, closes := ofKind(evs, "accept"), ofKind(evs, "close")
	if len(accepts) != 3 || len(closes) != 1 {
		t.Fatalf("events %+v", evs)
	}
	ok := accepts[0]
	if !ok.Handshake.OK || ok.PeerCertificate == nil || !strings.Contains(ok.PeerCertificate.Subject, "Brainpool P256 Client") ||
		ok.TICheck == nil || ok.TICheck.Result != "ok" || ok.Upstream != backend {
		t.Errorf("accept %+v", ok)
	}
	if c := closes[0]; c.Connection != ok.Connection || c.BytesReceived != 14 || c.BytesSent != 14 {
		t.Errorf("close %+v", c)
	}
	// In profile kt, the CertificateRequest of an ECDSA suite asks for
	// ecdsa_sign only, so the RSA client sends no certificate.
	if bad := accepts[1]; bad.Handshake.OK || bad.PeerCertificate != nil && (bad.TICheck == nil || bad.TICheck.Result != "failed") {
		t.Errorf("untrusted accept %+v %+v", bad.Handshake, bad.TICheck)
	}
	if none := accepts[2]; none.Handshake.OK || none.PeerCertificate != nil {
		t.Errorf("no-certificate accept %+v", none)
	}
}

// TestTunnelReverse runs a whole chain: plain text into tunnel, Brainpool
// TLS with client certificates from tunnel to reverse, plain text to the
// backend; with -client-auth request, a client without a certificate is
// let through too.
func TestTunnelReverse(t *testing.T) {
	backend := plainEcho(t)
	reverseAddr, stopReverse := startSidecar(t, "reverse", "-backend", backend, "-client-auth", "request",
		"-ca", pki+"bp256-ca.pem", "-cert", pki+"bp256-server.pem", "-key", pki+"bp256-server.key")
	tunnelAddr, stopTunnel := startSidecar(t, "tunnel", "-groups", "brainpoolP256r1", "-ca", pki+"bp256-ca.pem",
		"-cert", pki+"bp256-client.pem", "-key", pki+"bp256-client.key", reverseAddr)
	if got := tunnelRoundTrip(t, tunnelAddr, "through both\n"); got != "THROUGH BOTH\n" {
		t.Errorf("answer %q", got)
	}
	ca, _ := readCertificates(pki + "bp256-ca.pem")
	if got, err := tlsRoundTrip(t, reverseAddr, ti.ClientConfig(nil, &ti.Verifier{CAs: ca}), "anonymous"); err != nil || got != "ANONYMOUS" {
		t.Errorf("without a client certificate: %q, %v", got, err)
	}
	if out := stopTunnel(); !strings.Contains(out, "brainpoolP256r1") || !strings.Contains(out, "TI check ok") ||
		!strings.Contains(out, "client certificate sent") {
		t.Errorf("tunnel output:\n%s", out)
	}
	if out := stopReverse(); !strings.Contains(out, "client certificate CN=") || !strings.Contains(out, "no client certificate") ||
		!strings.Contains(out, "TI check ok") {
		t.Errorf("reverse output:\n%s", out)
	}
}

func TestReverseExposureWarning(t *testing.T) {
	for _, tc := range []struct {
		listen string
		auth   tls.ClientAuthType
		warn   bool
	}{
		{"localhost:8443", tls.NoClientCert, false},
		{"127.0.0.1:8443", tls.NoClientCert, false},
		{"[::1]:8443", tls.NoClientCert, false},
		{":8443", tls.NoClientCert, true},
		{"0.0.0.0:8443", tls.NoClientCert, true},
		{"10.0.0.5:8443", tls.NoClientCert, true},
		{"example.org:8443", tls.NoClientCert, true},
		{":8443", tls.RequestClientCert, false},
		{":8443", tls.RequireAnyClientCert, false},
	} {
		w := exposureWarning(tc.listen, "localhost:9000", tc.auth)
		if (w != "") != tc.warn || tc.warn && !strings.Contains(w, "localhost:9000") {
			t.Errorf("-listen %s, client auth %v: warning %q", tc.listen, tc.auth, w)
		}
	}
}

func TestReverseListenDefault(t *testing.T) {
	var stdout, stderr strings.Builder
	run([]string{"reverse", "-h"}, &stdout, &stderr)
	if !strings.Contains(stderr.String(), `(default "localhost:8443")`) {
		t.Errorf("-listen should default to localhost:8443; usage:\n%s", stderr.String())
	}
}
