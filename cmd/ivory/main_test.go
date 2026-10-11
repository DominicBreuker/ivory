//go:build ivory

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/cmd/ivory/internal/wire"
	"github.com/DominicBreuker/ivory/internal/testpki"
	"github.com/DominicBreuker/ivory/internal/tsltest"
	"github.com/DominicBreuker/ivory/ocsp"
	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
	"github.com/DominicBreuker/ivory/tsl"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const pki = "../../testdata/pki/"

// runCmd runs the command line and returns its exit status and output.
func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// startServer runs "ivory server -once" with args and returns its address
// and a channel with its output once it has handled one connection.
func startServer(t *testing.T, args ...string) (string, <-chan string) {
	t.Helper()
	lnc := make(chan net.Listener, 1)
	listen = func(network, addr string) (net.Listener, error) {
		ln, err := net.Listen(network, addr)
		if err == nil {
			lnc <- ln
		}
		return ln, err
	}
	t.Cleanup(func() { listen = net.Listen })
	out := make(chan string, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"server", "-addr", "127.0.0.1:0", "-once", "-idle", "2s"}, args...), &stdout, &stderr)
		if code != 0 {
			t.Errorf("server exited with %d: %s", code, stderr.String())
		}
		out <- stdout.String()
	}()
	select {
	case ln := <-lnc:
		return ln.Addr().String(), out
	case <-time.After(10 * time.Second):
		t.Fatal("server didn't start")
	}
	return "", nil
}

func TestUsage(t *testing.T) {
	if code, _, _ := runCmd(t); code != 2 {
		t.Errorf("no arguments: exit %d", code)
	}
	if code, _, _ := runCmd(t, "frobnicate"); code != 2 {
		t.Errorf("unknown command: exit %d", code)
	}
	if code, out, _ := runCmd(t, "help"); code != 0 || !strings.Contains(out, "ivory probe") {
		t.Errorf("help: exit %d", code)
	}
	if code, _, _ := runCmd(t, "client"); code != 2 {
		t.Errorf("client without address: exit %d", code)
	}
	if code, _, _ := runCmd(t, "probe", "-help"); code != 0 {
		t.Errorf("probe -help: exit %d", code)
	}
}

// TestProductionGuard checks that client and probe refuse the production
// environment without -allow-pu, before any network access.
func TestProductionGuard(t *testing.T) {
	for _, cmd := range []string{"client", "probe"} {
		code, _, stderr := runCmd(t, cmd, "-env", "pu", "127.0.0.1:1")
		if code != 1 || !strings.Contains(stderr, "-allow-pu") {
			t.Errorf("%s -env pu: exit %d, %q", cmd, code, stderr)
		}
	}
	if code, _, stderr := runCmd(t, "client", "-env", "xu", "127.0.0.1:1"); code != 1 || !strings.Contains(stderr, "unknown environment") {
		t.Errorf("-env xu: exit %d, %q", code, stderr)
	}
}

func TestClientServer(t *testing.T) {
	// The server has the Brainpool test identity and checks client
	// certificates against the test CA; the client presents its
	// Brainpool identity and checks the server's against the same CA.
	addr, out := startServer(t, "-json", "-cert", pki+"bp256-server.pem", "-key", pki+"bp256-server.key",
		"-ca", pki+"bp256-ca.pem", "-client-auth", "require")
	code, stdout, stderr := runCmd(t, "client", "-json", "-trace", "-cert", pki+"bp256-client.pem", "-key", pki+"bp256-client.key",
		"-ca", pki+"bp256-ca.pem", "-servername", "localhost", addr)
	if code != 0 {
		t.Fatalf("client: exit %d\n%s\n%s", code, stdout, stderr)
	}
	var cr clientReport
	if err := json.Unmarshal([]byte(stdout), &cr); err != nil {
		t.Fatal(err)
	}
	h := cr.Handshake
	if !h.OK || h.Version != wire.VersionTLS12 || !wire.CipherSuite(h.CipherSuite).IsECDSA() || h.Group == 0 || !h.ExtendedMasterSecret {
		t.Errorf("handshake %+v", h)
	}
	if cr.Server == nil || cr.Server.Certificates[0].Key != "ECDSA brainpoolP256r1" || cr.Server.TICheck == nil || cr.Server.TICheck.Result != "ok" {
		t.Errorf("server chain %+v", cr.Server)
	}
	if cr.CertificateRequest == nil || !slices.Contains(cr.CertificateRequest.CertificateTypes, "ecdsa_sign") ||
		cr.ClientCertificate == nil || !strings.Contains(cr.ClientCertificate.Subject, "Brainpool P256 Client") {
		t.Errorf("client auth %+v, sent %+v", cr.CertificateRequest, cr.ClientCertificate)
	}
	if len(cr.Trace) == 0 || cr.Trace[0].Dir != dirC2S || cr.Trace[0].Messages[0].Type != wire.TypeClientHello {
		t.Errorf("trace starts with %+v", cr.Trace)
	}

	var sr serverReport
	if err := json.Unmarshal([]byte(<-out), &sr); err != nil {
		t.Fatal(err)
	}
	if !sr.Handshake.OK || sr.ClientHello == nil || sr.ClientHello.ServerName != "localhost" ||
		!slices.Contains(sr.ClientHello.SupportedGroups, wire.Group(tlsutil.CurveBrainpoolP256r1)) || sr.ClientHello.JA3Hash == "" {
		t.Errorf("server report %+v", sr)
	}
	if sr.ClientCertificates == nil || sr.ClientCertificates.TICheck == nil || sr.ClientCertificates.TICheck.Result != "ok" {
		t.Errorf("client chain %+v", sr.ClientCertificates)
	}
}

func TestClientServerTLS13(t *testing.T) {
	// The server generates its identities; a TLS 1.3 client gets the
	// Brainpool one with ecdsa_brainpoolP256r1tls13_sha256. The client
	// trusts only the test CA, so the check fails: exit status 3.
	addr, out := startServer(t, "-profile", "tls13", "-client-auth", "none")
	code, stdout, stderr := runCmd(t, "client", "-profile", "tls13", "-groups", "brainpoolP256r1tls13",
		"-sigalgs", "ecdsa_brainpoolP256r1tls13_sha256", "-ca", pki+"bp256-ca.pem", addr)
	if code != 3 {
		t.Fatalf("client: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"TLS 1.3", "brainpoolP256r1tls13", "ECDSA brainpoolP256r1", "not issued by a trusted CA"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("client output lacks %q:\n%s", want, stdout)
		}
	}
	if s := <-out; !strings.Contains(s, "key shares") || !strings.Contains(s, "client cert       none") {
		t.Errorf("server output:\n%s", s)
	}
}

// connectProxy starts an HTTP proxy that answers one CONNECT with status
// and, for 200, relays the connection. The channel gets the request.
func connectProxy(t *testing.T, status int) (string, <-chan *http.Request) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	reqs := make(chan *http.Request, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			t.Error(err)
			return
		}
		reqs <- req
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n\r\n", status, http.StatusText(status))
		if status != http.StatusOK {
			return
		}
		up, err := net.Dial("tcp", req.Host)
		if err != nil {
			t.Error(err)
			return
		}
		defer up.Close()
		go io.Copy(up, c)
		io.Copy(c, up)
	}()
	return ln.Addr().String(), reqs
}

func TestClientProxy(t *testing.T) {
	addr, out := startServer(t, "-cert", pki+"bp256-server.pem", "-key", pki+"bp256-server.key")
	proxy, reqs := connectProxy(t, http.StatusOK)
	code, stdout, stderr := runCmd(t, "client", "-proxy", "http://ivory:secret@"+proxy, "-ca", pki+"bp256-ca.pem",
		"-servername", "localhost", addr)
	if code != 0 {
		t.Fatalf("client: exit %d\n%s\n%s", code, stdout, stderr)
	}
	// The test CA isn't a public root, so the web PKI check fails.
	if !strings.Contains(stdout, "via proxy http://"+proxy) || !strings.Contains(stdout, "brainpoolP256r1") ||
		!strings.Contains(stdout, "Web PKI check\n  result            FAILED") {
		t.Errorf("client output:\n%s", stdout)
	}
	req := <-reqs
	if req.Method != http.MethodConnect || req.Host != addr {
		t.Errorf("proxy got %s %s", req.Method, req.Host)
	}
	if user, pass, _ := (&http.Request{Header: http.Header{"Authorization": req.Header["Proxy-Authorization"]}}).BasicAuth(); user != "ivory" || pass != "secret" {
		t.Errorf("proxy credentials %q:%q", user, pass)
	}
	<-out

	// A refused CONNECT fails the command.
	proxy, _ = connectProxy(t, http.StatusForbidden)
	code, _, stderr = runCmd(t, "client", "-proxy", "http://"+proxy, "-timeout", "2s", "example.invalid:443")
	if code != 1 || !strings.Contains(stderr, "403 Forbidden") {
		t.Errorf("refused CONNECT: exit %d, %s", code, stderr)
	}
}

// socksProxy starts a SOCKS5 proxy (RFC 1928) that serves one CONNECT,
// with username and password (RFC 1929) if user isn't empty. The channel
// gets the address type and the address the client asked for.
func socksProxy(t *testing.T, user, pass string) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	reqs := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		fail := func(err error) { t.Errorf("socks proxy: %v", err) }
		read := func(n int) []byte {
			b := make([]byte, n)
			if _, err := io.ReadFull(c, b); err != nil {
				fail(err)
				return nil
			}
			return b
		}
		h := read(2)
		if h == nil || !slices.Contains(read(int(h[1])), map[bool]byte{false: 0, true: 2}[user != ""]) {
			fail(fmt.Errorf("methods"))
			return
		}
		if user == "" {
			c.Write([]byte{5, 0})
		} else {
			c.Write([]byte{5, 2})
			v := read(2)
			u := string(read(int(v[1])))
			p := string(read(int(read(1)[0])))
			if u != user || p != pass {
				c.Write([]byte{1, 1})
				return
			}
			c.Write([]byte{1, 0})
		}
		r := read(4)
		var target, kind string
		switch r[3] {
		case 1:
			kind, target = "ipv4", net.IP(read(4)).String()
		case 4:
			kind, target = "ipv6", net.IP(read(16)).String()
		case 3:
			kind, target = "domain", string(read(int(read(1)[0])))
		}
		port := read(2)
		addr := net.JoinHostPort(target, fmt.Sprint(int(port[0])<<8|int(port[1])))
		reqs <- kind + " " + addr
		dial := addr
		if strings.HasSuffix(target, ".test") {
			// Names under .test (RFC 2606) stand for this host.
			dial = net.JoinHostPort("127.0.0.1", fmt.Sprint(int(port[0])<<8|int(port[1])))
		}
		up, err := net.Dial("tcp", dial)
		if err != nil {
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		go io.Copy(up, c)
		io.Copy(c, up)
	}()
	return ln.Addr().String(), reqs
}

func TestClientSOCKS5(t *testing.T) {
	// socks5h sends the host name to the proxy, as ssh -D expects.
	addr, out := startServer(t, "-cert", pki+"bp256-server.pem", "-key", pki+"bp256-server.key")
	_, port, _ := net.SplitHostPort(addr)
	proxy, reqs := socksProxy(t, "", "")
	code, stdout, stderr := runCmd(t, "client", "-proxy", "socks5h://"+proxy, "-ca", pki+"bp256-ca.pem", "localhost:"+port)
	if code != 0 {
		t.Fatalf("client: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "via proxy socks5h://"+proxy) || !strings.Contains(stdout, "brainpoolP256r1") {
		t.Errorf("client output:\n%s", stdout)
	}
	if r := <-reqs; r != "domain localhost:"+port {
		t.Errorf("proxy got %q", r)
	}
	<-out

	// socks5 with a password sends an address.
	addr, out = startServer(t, "-cert", pki+"bp256-server.pem", "-key", pki+"bp256-server.key")
	proxy, reqs = socksProxy(t, "ivory", "secret")
	code, stdout, stderr = runCmd(t, "client", "-proxy", "socks5://ivory:secret@"+proxy, "-ca", pki+"bp256-ca.pem",
		"-servername", "localhost", addr)
	if code != 0 {
		t.Fatalf("client: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if r := <-reqs; r != "ipv4 "+addr {
		t.Errorf("proxy got %q", r)
	}
	<-out

	// A wrong password and a refused connection fail the command.
	proxy, _ = socksProxy(t, "ivory", "secret")
	code, _, stderr = runCmd(t, "client", "-proxy", "socks5h://ivory:wrong@"+proxy, "-timeout", "2s", "server.invalid:443")
	if code != 1 || !strings.Contains(stderr, "refused the username and password") {
		t.Errorf("wrong password: exit %d, %s", code, stderr)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	proxy, _ = socksProxy(t, "", "")
	code, _, stderr = runCmd(t, "client", "-proxy", "socks5://"+proxy, "-timeout", "2s", closed)
	if code != 1 || !strings.Contains(stderr, "connection refused") {
		t.Errorf("refused connection: exit %d, %s", code, stderr)
	}
}

func TestProxyFlag(t *testing.T) {
	for _, tt := range []struct {
		flag, want string
		bad        bool
	}{
		{flag: "direct"},
		{flag: "http://127.0.0.1:3128", want: "127.0.0.1:3128"},
		{flag: "socks5://127.0.0.1:1080", want: "127.0.0.1:1080"},
		{flag: "socks5h://localhost:1080", want: "localhost:1080"},
		{flag: "https://127.0.0.1:3128", bad: true},
		{flag: "127.0.0.1:3128", bad: true},
	} {
		d := &dialer{proxy: tt.flag}
		u, err := d.proxyFor("server.example:443")
		switch {
		case tt.bad && err == nil:
			t.Errorf("-proxy %s: no error", tt.flag)
		case !tt.bad && err != nil:
			t.Errorf("-proxy %s: %v", tt.flag, err)
		case !tt.bad && tt.want == "" && u != nil, tt.want != "" && (u == nil || u.Host != tt.want):
			t.Errorf("-proxy %s: %v", tt.flag, u)
		}
	}
}

func TestClientHandshakeFailure(t *testing.T) {
	// A TLS 1.3-only client against the ti profile (TLS 1.2 only).
	addr, out := startServer(t)
	code, stdout, _ := runCmd(t, "client", "-profile", "tls13", addr)
	if code != 1 || !strings.Contains(stdout, "FAILED") || !strings.Contains(stdout, "protocol_version") {
		t.Errorf("exit %d:\n%s", code, stdout)
	}
	if s := <-out; !strings.Contains(s, "alert sent        fatal protocol_version") {
		t.Errorf("server output:\n%s", s)
	}
}

func loadPair(t *testing.T, name string) tls.Certificate {
	t.Helper()
	c, err := loadIdentity(pki+name+".pem", pki+name+".key")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// serveTLS serves config on a local port until the test ends.
func serveTLS(t *testing.T, config *tls.Config) string {
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
				s := tls.Server(c, config)
				if s.Handshake() == nil {
					io.Copy(io.Discard, s)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func probe(t *testing.T, addr string, args ...string) *probeReport {
	t.Helper()
	code, stdout, stderr := runCmd(t, append(append([]string{"probe", "-json", "-delay", "0"}, args...), addr)...)
	if code != 0 {
		t.Fatalf("probe: exit %d\n%s", code, stderr)
	}
	var r probeReport
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func supported[T comparable](results []itemResult, conv func(itemResult) T) []T {
	var out []T
	for _, r := range results {
		if r.Supported {
			out = append(out, conv(r))
		}
	}
	return out
}

// TestProbeTI probes a server with the ti preset and a Brainpool and an
// RSA identity, as an eHealth-KT has.
func TestProbeTI(t *testing.T) {
	addr := serveTLS(t, ti.ServerConfig([]tls.Certificate{loadPair(t, "bp256-server"), loadPair(t, "rsa-server")}, nil))
	r := probe(t, addr, "-ca", pki+"bp256-ca.pem")
	for _, v := range r.Versions {
		if v.Supported != (v.Version == wire.VersionTLS12) {
			t.Errorf("version %v: %+v", v.Version, v)
		}
	}
	got := r.Suites["TLS 1.2"].Suites
	slices.Sort(got)
	if want := []wire.CipherSuite{0xc02b, 0xc02c, 0xc02f, 0xc030}; !slices.Equal(got, want) {
		t.Errorf("suites %v, want %v", got, want)
	}
	groups := supported(r.Groups12.Results, func(i itemResult) wire.Group { return i.Group })
	if want := []wire.Group{0x0017, 0x0018, 0x001a, 0x001b}; !slices.Equal(groups, want) {
		t.Errorf("groups %v, want %v", groups, want)
	}
	var schemes []wire.SignatureScheme
	for _, s := range r.Schemes12 {
		if s.Supported {
			schemes = append(schemes, s.Scheme)
		}
	}
	for _, want := range []wire.SignatureScheme{0x0403, 0x0804, 0x0401} {
		if !slices.Contains(schemes, want) {
			t.Errorf("scheme %v missing from %v", want, schemes)
		}
	}
	if slices.Contains(schemes, 0x0807) {
		t.Errorf("ed25519 among %v", schemes)
	}
	if len(r.Certs) != 2 {
		t.Fatalf("%d certificates", len(r.Certs))
	}
	var keys []string
	for _, c := range r.Certs {
		keys = append(keys, c.Certificates[0].Key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"ECDSA brainpoolP256r1", "RSA 2048"}) {
		t.Errorf("keys %v", keys)
	}
	for _, c := range r.Certs {
		if c.TICheck == nil || (c.TICheck.Result == "ok") != (c.Certificates[0].Key == "ECDSA brainpoolP256r1") {
			t.Errorf("TI check of %s: %+v", c.Certificates[0].Key, c.TICheck)
		}
	}
	if !strings.HasPrefix(r.Fallback, "not applicable") || r.Extensions == nil || !r.Extensions.ExtendedMasterSecret ||
		!r.Extensions.SecureRenegotiation || r.Extensions.SessionTicket || len(r.ClientAuth) != 0 {
		t.Errorf("fallback %q, extensions %+v, client auth %+v", r.Fallback, r.Extensions, r.ClientAuth)
	}
	if !slices.Contains(r.TI, "TI TLS 1.2 cipher suites supported: 4 of 4") {
		t.Errorf("TI observations %q", r.TI)
	}
}

// TestProbeTLS13 probes a TLS 1.3 server with a Brainpool identity
// (RFC 8734) that also requests a client certificate.
func TestSchemes13(t *testing.T) {
	// The TLS 1.3 scheme probe offers one scheme for the handshake
	// signature and keeps the certificate-only schemes in
	// signature_algorithms_cert.
	for _, s := range []wire.SignatureScheme{0x0804, 0x0503, 0x081a} {
		c, srv := net.Pipe()
		go func() {
			tls.Client(c, &tls.Config{
				MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true,
				SignatureSchemes:           schemes13(s),
				VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
			}).Handshake()
			c.Close()
		}()
		var st wire.Stream
		var ch *wire.ClientHello
		buf := make([]byte, 4096)
		for ch == nil {
			n, err := srv.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range st.Feed(buf[:n]) {
				for _, m := range e.Messages {
					if m.Type == wire.TypeClientHello {
						if ch, err = wire.ParseClientHello(m.Body); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
		}
		srv.Close()
		if !slices.Equal(ch.SignatureAlgorithms, []wire.SignatureScheme{s}) {
			t.Errorf("%v: signature_algorithms %v", s, ch.SignatureAlgorithms)
		}
		if !slices.Contains(ch.SignatureAlgorithmsCert, s) || !slices.Contains(ch.SignatureAlgorithmsCert, 0x0401) {
			t.Errorf("%v: signature_algorithms_cert %v", s, ch.SignatureAlgorithmsCert)
		}
	}
}

func TestProbeTLS13(t *testing.T) {
	cfg := &tls.Config{
		MinVersion:                 tls.VersionTLS12,
		Certificates:               []tls.Certificate{loadPair(t, "bp256-server")},
		CurvePreferences:           []tls.CurveID{tlsutil.CurveBrainpoolP256r1TLS13, tlsutil.CurveBrainpoolP384r1TLS13, tlsutil.CurveBrainpoolP256r1, tls.CurveP256},
		KeyExchanges:               tlsutil.KeyExchanges(brainpool.P256r1(), brainpool.P384r1()),
		SignatureSchemes:           tlsutil.SignatureSchemes(),
		VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
		ClientAuth:                 tls.RequestClientCert,
	}
	r := probe(t, serveTLS(t, cfg), "-cert", pki+"bp256-client.pem", "-key", pki+"bp256-client.key")
	if !r.supports(wire.VersionTLS13) || !r.supports(wire.VersionTLS12) {
		t.Errorf("versions %+v", r.Versions)
	}
	groups := supported(r.Groups13.Results, func(i itemResult) wire.Group { return i.Group })
	if want := []wire.Group{0x0017, 0x001f, 0x0020}; !slices.Equal(groups, want) {
		t.Errorf("TLS 1.3 groups %v, want %v", groups, want)
	}
	var schemes []wire.SignatureScheme
	for _, s := range r.Schemes13 {
		if s.Supported {
			schemes = append(schemes, s.Scheme)
		}
	}
	if !slices.Equal(schemes, []wire.SignatureScheme{0x081a}) {
		t.Errorf("TLS 1.3 schemes %v", schemes)
	}
	if !strings.HasPrefix(r.Fallback, "enforced") {
		t.Errorf("fallback %q", r.Fallback)
	}
	var v13 bool
	for _, ca := range r.ClientAuth {
		if ca.Version == wire.VersionTLS13 && slices.Contains(ca.SignatureSchemes, 0x081a) {
			v13 = true
		}
	}
	if !v13 {
		t.Errorf("client auth %+v", r.ClientAuth)
	}
}

// admission returns an admission extension with one profession.
func admission(item, oid, reg string) pkix.Extension {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // contentsOfAdmissions
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // Admissions
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // professionInfos
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ProfessionInfo
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(item)) })
						})
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							o, _ := x509.ParseOID(oid)
							der, _ := o.MarshalBinary()
							b.AddASN1(cbasn1.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) { b.AddBytes(der) })
						})
						b.AddASN1(cbasn1.PrintableString, func(b *cryptobyte.Builder) { b.AddBytes([]byte(reg)) })
					})
				})
			})
		})
	})
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3}, Value: b.BytesOrPanic()}
}

func writePEM(t *testing.T, dir, name string, der []byte) string {
	t.Helper()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestTSLCheck checks a server certificate against a TSL with an OCSP
// responder, all with Brainpool keys: the client's TI check finds the CA
// in the TSL and asks the OCSP responder named there.
func TestTSLCheck(t *testing.T) {
	bp := func() crypto.Signer { return testpki.Brainpool(t, brainpool.P256r1()) }
	anchorKey, signerKey, caKey, ocspKey, leafKey := bp(), bp(), bp(), bp(), testpki.Brainpool(t, brainpool.P256r1())
	anchor := testpki.Issue(t, testpki.CA("GEM.TSL-CA-TEST"), anchorKey, nil, anchorKey)
	signer := testpki.Issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "TSL Signing Unit TEST"},
		KeyUsage:              x509.KeyUsageContentCommitment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{tsl.OIDTSLSigning},
		BasicConstraintsValid: true,
	}, signerKey, anchor, anchorKey)
	ca := testpki.Issue(t, testpki.CA("GEM.KOMP-CA-TEST"), caKey, nil, caKey)
	responder := testpki.Issue(t, testpki.EE("OCSP Signer", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageOCSPSigning), ocspKey, ca, caKey)
	tmpl := testpki.EE("fachdienst.example", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageServerAuth)
	tmpl.DNSNames = []string{"localhost"}
	tmpl.Policies = []x509.OID{ti.PolicyFDTLSS}
	tmpl.ExtraExtensions = []pkix.Extension{admission("E-Rezept", "1.2.276.0.76.4.259", "123")}
	leaf := testpki.Issue(t, tmpl, leafKey, ca, caKey)

	ocspSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := ocsp.NewCertID(leaf, ca, crypto.SHA1)
		if err != nil {
			t.Error(err)
		}
		now := time.Now()
		der, err := ocsp.CreateResponse(ocsp.ResponseTemplate{
			ProducedAt: now,
			Responses: []ocsp.SingleResponse{{CertID: id, Status: ocsp.Good, ThisUpdate: now, NextUpdate: now.Add(time.Hour),
				CertHash: ocsp.NewCertHash(leaf)}},
			Certificates: [][]byte{responder.Raw},
		}, responder, ocspKey)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(der)
	}))
	defer ocspSrv.Close()

	unsigned := tsltest.XML(1, time.Now().Add(30*24*time.Hour), "http://tsl.example/tsl.xml", "http://tsl-backup.example/tsl.xml",
		tsltest.Service{Type: tsl.TypeCA, Certs: []*x509.Certificate{ca}, SupplyPoints: []string{ocspSrv.URL},
			ExtensionOIDs: []string{ti.PolicyFDTLSS.String()}, Name: "GEM.KOMP-CA-TEST"},
		tsltest.Service{Type: tsl.TypeOCSP, Certs: []*x509.Certificate{responder}, Name: "OCSP"})
	dir := t.TempDir()
	tslFile := filepath.Join(dir, "tsl.xml")
	if err := os.WriteFile(tslFile, tsltest.Sign(t, unsigned, signer, signerKey), 0o644); err != nil {
		t.Fatal(err)
	}
	anchorFile := writePEM(t, dir, "anchor.pem", anchor.Raw)

	id, err := tlsutil.Certificate([][]byte{leaf.Raw}, tlsutil.NewSigner(leafKey))
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTLS(t, ti.ServerConfig([]tls.Certificate{id}, nil))
	code, stdout, stderr := runCmd(t, "client", "-json", "-tsl", tslFile, "-trust-anchor", anchorFile, addr)
	if code != 0 {
		t.Fatalf("client: exit %d\n%s\n%s", code, stdout, stderr)
	}
	var cr clientReport
	if err := json.Unmarshal([]byte(stdout), &cr); err != nil {
		t.Fatal(err)
	}
	c, check := cr.Server.Certificates[0], cr.Server.TICheck
	if check.Result != "ok" || check.OCSP != "good" || check.IssuerService != "GEM.KOMP-CA-TEST" || check.TSLSequence != 1 || check.OCSPResponder != ocspSrv.URL {
		t.Errorf("TI check %+v", check)
	}
	if !slices.Equal(c.Types, []string{"C.FD.TLS-S"}) || c.Admission == nil || len(c.Admission.Professions) != 1 {
		t.Fatalf("certificate %+v", c)
	}
	p := c.Admission.Professions[0]
	if !slices.Equal(p.Items, []string{"E-Rezept"}) || len(p.OIDs) != 1 || !strings.Contains(p.OIDs[0].Name, "oid_erezept") || p.RegistrationNumber != "123" {
		t.Errorf("admission %+v", p)
	}
	if !strings.Contains(stderr, "TSL sequence 1") {
		t.Errorf("stderr %q", stderr)
	}

	// A TSL signed under another anchor is refused.
	otherKey := bp()
	other := testpki.Issue(t, testpki.CA("GEM.TSL-CA-OTHER"), otherKey, nil, otherKey)
	otherFile := writePEM(t, dir, "other.pem", other.Raw)
	if code, _, stderr := runCmd(t, "client", "-tsl", tslFile, "-trust-anchor", otherFile, addr); code != 1 || !strings.Contains(stderr, "TSL") {
		t.Errorf("wrong anchor: exit %d, %q", code, stderr)
	}
}

func TestGeneratedIdentities(t *testing.T) {
	certs, err := generateIdentities([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, c := range certs {
		info := describeDER(c.Certificate[0])
		keys = append(keys, info.Key)
		if !slices.Equal(info.DNSNames, []string{"localhost"}) || !slices.Equal(info.IPs, []string{"127.0.0.1"}) {
			t.Errorf("names %v %v", info.DNSNames, info.IPs)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := (&ti.Verifier{CAs: []*x509.Certificate{caFromSelfSigned(leaf)}}).Verify(leaf, "localhost"); err != nil {
			t.Errorf("%s: %v", info.Key, err)
		}
		if sum := sha256.Sum256(c.Certificate[0]); info.SHA256 == "" || sum[0] == 0 && sum[1] == 0 {
			t.Errorf("hash")
		}
	}
	if !slices.Equal(keys, []string{"ECDSA brainpoolP256r1", "ECDSA P-256", "RSA 2048"}) {
		t.Errorf("keys %v", keys)
	}
}

// caFromSelfSigned returns a copy of a self-signed end-entity certificate
// that ti.Verifier accepts as its issuing CA: same subject and key.
func caFromSelfSigned(c *x509.Certificate) *x509.Certificate {
	ca := *c
	ca.IsCA, ca.BasicConstraintsValid, ca.KeyUsage = true, true, 0
	return &ca
}
