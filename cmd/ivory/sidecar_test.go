//go:build ivory

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/cmd/ivory/internal/wire"
	"github.com/DominicBreuker/ivory/ti"
)

// syncBuffer is a bytes.Buffer for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// startSidecar runs the command line (tunnel or proxy) and returns its
// listen address and a function that stops it and returns its output.
func startSidecar(t *testing.T, args ...string) (string, func() string) {
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
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(append(args[:1:1], append([]string{"-listen", "127.0.0.1:0"}, args[1:]...)...), &stdout, &stderr)
	}()
	var ln net.Listener
	select {
	case ln = <-lnc:
	case code := <-done:
		t.Fatalf("%s exited with %d: %s", args[0], code, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatalf("%s didn't start", args[0])
	}
	var once sync.Once
	stop := func() string {
		once.Do(func() {
			ln.Close()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Errorf("%s didn't stop", args[0])
			}
		})
		return stdout.String()
	}
	t.Cleanup(func() { stop() })
	return ln.Addr().String(), stop
}

// events parses the JSON lines of a sidecar.
func events(t *testing.T, out string) []sidecarEvent {
	t.Helper()
	var evs []sidecarEvent
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var ev sidecarEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		evs = append(evs, ev)
	}
	return evs
}

func ofKind(evs []sidecarEvent, kind string) []sidecarEvent {
	var out []sidecarEvent
	for _, ev := range evs {
		if ev.Event == kind {
			out = append(out, ev)
		}
	}
	return out
}

// echoServer serves config and answers each connection with what the
// client sent, in upper case, once the client has closed its side.
func echoServer(t *testing.T, config *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
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
				c.Write(bytes.ToUpper(b))
			}()
		}
	}()
	return ln.Addr().String()
}

// tunnelRoundTrip sends msg through the tunnel at addr and returns the
// answer.
func tunnelRoundTrip(t *testing.T, addr, msg string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).CloseWrite()
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestTunnel(t *testing.T) {
	// A Brainpool server that requires a client certificate of the test
	// CA; the tunnel presents the Brainpool client identity and checks
	// the server's against the same CA.
	ca, err := readCertificates(pki + "bp256-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	upstreamAddr := echoServer(t, ti.ServerConfig([]tls.Certificate{loadPair(t, "bp256-server")}, &ti.Verifier{CAs: ca}))
	addr, stop := startSidecar(t, "tunnel", "-json", "-groups", "brainpoolP256r1", "-ca", pki+"bp256-ca.pem",
		"-cert", pki+"bp256-client.pem", "-key", pki+"bp256-client.key", upstreamAddr)
	if got := tunnelRoundTrip(t, addr, "hello brainpool\n"); got != "HELLO BRAINPOOL\n" {
		t.Errorf("answer %q", got)
	}
	if got := tunnelRoundTrip(t, addr, "again\n"); got != "AGAIN\n" {
		t.Errorf("second answer %q", got)
	}
	evs := events(t, stop())
	connects, closes := ofKind(evs, "connect"), ofKind(evs, "close")
	if len(connects) != 2 || len(closes) != 2 {
		t.Fatalf("events %+v", evs)
	}
	ev := connects[0]
	if h := ev.Handshake; h == nil || !h.OK || h.Version != wire.VersionTLS12 || h.Group != wire.Group(0x1a) {
		t.Errorf("handshake %+v", ev.Handshake)
	}
	if ev.Verify != "ti" || ev.TICheck == nil || ev.TICheck.Result != "ok" || ev.Server == nil || ev.Server.Key != "ECDSA brainpoolP256r1" {
		t.Errorf("check %s %+v, server %+v", ev.Verify, ev.TICheck, ev.Server)
	}
	if ev.ClientCertificate == nil || !strings.Contains(ev.ClientCertificate.Subject, "Brainpool P256 Client") {
		t.Errorf("client certificate %+v", ev.ClientCertificate)
	}
	if c := closes[0]; c.BytesSent != 16 || c.BytesReceived != 16 {
		t.Errorf("close %+v", c)
	}
}

func TestTunnelCheckFails(t *testing.T) {
	upstreamAddr := echoServer(t, ti.ServerConfig([]tls.Certificate{loadPair(t, "bp256-server")}, nil))
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"ti", []string{"-ca", pki + "bp256-evil-ca.pem"}, "TI check FAILED"},
		{"webpki", []string{"-servername", "localhost"}, "web PKI check FAILED"},
		{"no name", nil, "no server name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, stop := startSidecar(t, append(append([]string{"tunnel"}, tc.args...), upstreamAddr)...)
			if got := tunnelRoundTrip(t, addr, "secret\n"); got != "" {
				t.Errorf("answer %q through a tunnel whose check failed", got)
			}
			if out := stop(); !strings.Contains(out, tc.want) || !strings.Contains(out, "handshake FAILED") {
				t.Errorf("output lacks %q:\n%s", tc.want, out)
			}
		})
	}
	// -verify none connects anyway.
	addr, stop := startSidecar(t, "tunnel", "-verify", "none", upstreamAddr)
	if got := tunnelRoundTrip(t, addr, "x"); got != "X" {
		t.Errorf("-verify none: answer %q", got)
	}
	if out := stop(); !strings.Contains(out, "NOT checked") {
		t.Errorf("-verify none output:\n%s", out)
	}
}

func TestProxy(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ti.ServerConfig([]tls.Certificate{loadPair(t, "bp256-server")}, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s uri=%s tls=%x proxy-header=%q", r.Host, r.RequestURI, r.TLS.Version, r.Header.Get("Proxy-Connection"))
	}))
	upstreamAddr := ln.Addr().String()
	_, port, _ := net.SplitHostPort(upstreamAddr)

	addr, stop := startSidecar(t, "proxy", "-json", "-ca", pki+"bp256-ca.pem", "-allow", "localhost:"+port+",example.org")
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	get := func(u string) (int, string) {
		t.Helper()
		resp, err := client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, path := range []string{"/a?b=c", "/d"} {
		code, body := get("http://localhost:" + port + path)
		if want := "host=localhost:" + port + " uri=" + path + " tls=303 proxy-header=\"\""; code != 200 || body != want {
			t.Errorf("GET %s: %d %q, want %q", path, code, body, want)
		}
	}
	if code, body := get("http://127.0.0.1:" + port + "/"); code != http.StatusForbidden || !strings.Contains(body, "not an allowed target") {
		t.Errorf("not allowed: %d %q", code, body)
	}

	// CONNECT and requests in origin form are refused.
	for req, want := range map[string]int{
		"CONNECT localhost:" + port + " HTTP/1.1\r\nHost: localhost:" + port + "\r\n\r\n": http.StatusMethodNotAllowed,
		"GET / HTTP/1.1\r\nHost: " + addr + "\r\n\r\n":                                    http.StatusBadRequest,
	} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, req)
		if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != want {
			t.Errorf("%q: %v %v", req, resp, err)
		}
		c.Close()
	}

	client.CloseIdleConnections()
	evs := events(t, stop())
	connects, requests, refused := ofKind(evs, "connect"), ofKind(evs, "request"), ofKind(evs, "refused")
	if len(connects) != 1 || len(requests) != 2 || len(refused) != 3 {
		t.Fatalf("events %+v", evs)
	}
	if ev := connects[0]; !ev.Handshake.OK || ev.TICheck == nil || ev.TICheck.Result != "ok" || ev.ServerName != "localhost" {
		t.Errorf("connect %+v", ev)
	}
	for _, r := range requests {
		if r.Status != "200 OK" || r.Connection != connects[0].Connection || r.BytesReceived == 0 {
			t.Errorf("request %+v", r)
		}
	}
}

func TestProxyUpstreamFails(t *testing.T) {
	// The server's certificate fails the web PKI check: 502.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ti.ServerConfig([]tls.Certificate{loadPair(t, "bp256-server")}, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secret") }))
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	addr, stop := startSidecar(t, "proxy", "-allow", "*")
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	resp, err := client.Get("http://localhost:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(b), "secret") {
		t.Errorf("%d %q", resp.StatusCode, b)
	}
	if out := stop(); !strings.Contains(out, "web PKI check FAILED") {
		t.Errorf("output:\n%s", out)
	}
}

// TestSidecarGuards checks the refusals before any connection.
func TestSidecarGuards(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"proxy"}, 1, "-allow"},
		{[]string{"proxy", "-allow", "a:b:c"}, 1, "-allow"},
		{[]string{"proxy", "-allow", "*", "-listen", ":8080"}, 1, "-allow-remote"},
		{[]string{"tunnel", "-listen", "0.0.0.0:8443", "host"}, 1, "-allow-remote"},
		{[]string{"tunnel", "-listen", "192.0.2.1:8443", "host"}, 1, "-allow-remote"},
		{[]string{"tunnel", "-env", "pu", "host"}, 1, "-allow-pu"},
		{[]string{"proxy", "-allow", "*", "-env", "pu"}, 1, "-allow-pu"},
		{[]string{"tunnel", "-verify", "ti", "host"}, 1, "-verify ti needs"},
		{[]string{"tunnel", "-verify", "maybe", "host"}, 1, "-verify"},
		{[]string{"tunnel"}, 2, ""},
		{[]string{"reverse"}, 2, ""},
		{[]string{"reverse", "-backend", "192.0.2.1:80"}, 1, "-allow-remote"},
		{[]string{"reverse", "-backend", "localhost"}, 1, "-backend"},
		{[]string{"reverse", "-backend", "localhost:80", "-client-auth", "require"}, 1, "needs -env, -tsl or -ca"},
		{[]string{"reverse", "-backend", "localhost:80", "-client-auth", "maybe"}, 1, "-client-auth"},
	} {
		code, _, stderr := runCmd(t, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d, %q", tc.args, code, stderr)
		}
	}
}

func TestAllowList(t *testing.T) {
	l, err := parseAllow([]string{"idp-ref.app.ti-dienste.de, *.vzd.ti-dienste.de:443", "[::1]:8443", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]bool{
		"idp-ref.app.ti-dienste.de:443":            true,
		"IDP-REF.app.ti-dienste.de:8443":           true,
		"fhir-directory-ref.vzd.ti-dienste.de:443": true,
		"a.b.vzd.ti-dienste.de:443":                true,
		"vzd.ti-dienste.de:443":                    false,
		"fhir-directory-ref.vzd.ti-dienste.de:80":  false,
		"evilvzd.ti-dienste.de:443":                false,
		"idp-test.app.ti-dienste.de:443":           false,
		"[::1]:8443":                               true,
		"[::1]:443":                                false,
		"10.0.0.1:1":                               true,
		"10.0.0.2:1":                               false,
		"no-port":                                  false,
	} {
		if got := l.allows(target); got != want {
			t.Errorf("allows(%q) = %v", target, got)
		}
	}
	anyRule, _ := parseAllow([]string{"*:443"})
	if !anyRule.allows("example.com:443") || anyRule.allows("example.com:80") {
		t.Error("*:443")
	}
	for _, bad := range []string{"*.", "a*.b", "*.*.b", "host:x"} {
		if _, err := parseAllow([]string{bad}); err == nil {
			t.Errorf("parseAllow(%q) accepted", bad)
		}
	}
}

// TestSidecarUpstreamProxies checks that tunnel connects through HTTP
// CONNECT and SOCKS5 proxies, named by -proxy or by the environment.
func TestSidecarUpstreamProxies(t *testing.T) {
	upstreamAddr := echoServer(t, ti.ServerConfig([]tls.Certificate{loadPair(t, "bp256-server")}, nil))
	_, port, _ := net.SplitHostPort(upstreamAddr)
	// Names under .test reach this host through socksProxy only.
	named := "upstream.test:" + port
	for _, tc := range []struct {
		name   string
		start  func() (string, <-chan string)
		target string
		want   string // what the proxy saw
	}{
		{"http", func() (string, <-chan string) {
			p, reqs := connectProxy(t, http.StatusOK)
			out := make(chan string, 1)
			go func() { r := <-reqs; out <- r.Method + " " + r.Host }()
			return "http://ivory:secret@" + p, out
		}, upstreamAddr, "CONNECT " + upstreamAddr},
		{"socks5h", func() (string, <-chan string) {
			p, reqs := socksProxy(t, "", "")
			return "socks5h://" + p, reqs
		}, named, "domain " + named},
		{"socks5 with password", func() (string, <-chan string) {
			p, reqs := socksProxy(t, "ivory", "secret")
			return "socks5://ivory:secret@" + p, reqs
		}, upstreamAddr, "ipv4 " + upstreamAddr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy, reqs := tc.start()
			addr, stop := startSidecar(t, "tunnel", "-json", "-proxy", proxy, "-ca", pki+"bp256-ca.pem", tc.target)
			if got := tunnelRoundTrip(t, addr, "via proxy"); got != "VIA PROXY" {
				t.Errorf("answer %q", got)
			}
			if r := <-reqs; r != tc.want {
				t.Errorf("proxy saw %q, want %q", r, tc.want)
			}
			u, _ := url.Parse(proxy)
			if c := ofKind(events(t, stop()), "connect"); len(c) != 1 || c[0].Proxy != u.Scheme+"://"+u.Host || !c[0].Handshake.OK {
				t.Errorf("connect events %+v", c)
			}
		})
	}

	// The environment: HTTPS_PROXY, else ALL_PROXY, as ssh -D users set it.
	for _, v := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(v, "")
	}
	for _, env := range []string{"HTTPS_PROXY", "ALL_PROXY"} {
		t.Run(env, func(t *testing.T) {
			p, reqs := socksProxy(t, "", "")
			t.Setenv(env, "socks5h://"+p)
			t.Setenv("NO_PROXY", "localhost,127.0.0.1,example.org")
			addr, stop := startSidecar(t, "tunnel", "-ca", pki+"bp256-ca.pem", named)
			if got := tunnelRoundTrip(t, addr, "env"); got != "ENV" {
				t.Errorf("answer %q", got)
			}
			if r := <-reqs; r != "domain "+named {
				t.Errorf("proxy saw %q", r)
			}
			if out := stop(); !strings.Contains(out, "via proxy socks5h://"+p) {
				t.Errorf("output:\n%s", out)
			}
		})
	}
}

// TestProxyUpstreamSOCKS5 checks proxy through a SOCKS5 proxy.
func TestProxyUpstreamSOCKS5(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ti.ServerConfig([]tls.Certificate{loadPair(t, "bp256-server")}, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "host="+r.Host) }))
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	socks, reqs := socksProxy(t, "", "")
	addr, stop := startSidecar(t, "proxy", "-proxy", "socks5h://"+socks, "-allow", "*.test", "-ca", pki+"bp256-ca.pem")
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	resp, err := client.Get("http://upstream.test:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "host=upstream.test:"+port {
		t.Errorf("%d %q", resp.StatusCode, b)
	}
	if r := <-reqs; r != "domain upstream.test:"+port {
		t.Errorf("proxy saw %q", r)
	}
	client.CloseIdleConnections()
	if out := stop(); !strings.Contains(out, "via proxy socks5h://"+socks) {
		t.Errorf("output:\n%s", out)
	}
}

// TestDownloadsThroughProxy checks that the TSL and OCSP client uses the
// -proxy too.
func TestDownloadsThroughProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "tsl") }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	socks, reqs := socksProxy(t, "", "")
	d := &dialer{proxy: "socks5h://" + socks, timeout: 5 * time.Second}
	b, err := get(t.Context(), d.httpClient(), "http://tsl.test:"+port+"/tsl.xml")
	if err != nil || string(b) != "tsl" {
		t.Fatalf("%q, %v", b, err)
	}
	if r := <-reqs; r != "domain tsl.test:"+port {
		t.Errorf("proxy saw %q", r)
	}
}

func TestEnvProxy(t *testing.T) {
	for _, v := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(v, "")
	}
	t.Setenv("ALL_PROXY", "socks5h://localhost:1080")
	t.Setenv("no_proxy", "10.0.0.0/8, .internal.example,direct.example:8443,[2001:db8::1],*.svc.local")
	for addr, want := range map[string]string{
		"idp-ref.app.ti-dienste.de:443": "socks5h://localhost:1080",
		"localhost:443":                 "",
		"127.0.0.1:443":                 "",
		"[::1]:443":                     "",
		"10.1.2.3:443":                  "",
		"11.1.2.3:443":                  "socks5h://localhost:1080",
		"a.internal.example:443":        "",
		"internal.example:443":          "",
		"xinternal.example:443":         "socks5h://localhost:1080",
		"direct.example:8443":           "",
		"direct.example:443":            "socks5h://localhost:1080",
		"[2001:db8::1]:443":             "",
		"x.svc.local:443":               "",
	} {
		u, err := envProxy(addr)
		got := ""
		if u != nil {
			got = u.String()
		}
		if err != nil || got != want {
			t.Errorf("envProxy(%s) = %q, %v; want %q", addr, got, err, want)
		}
	}
	// HTTPS_PROXY wins over ALL_PROXY; a bare host:port is an HTTP proxy.
	t.Setenv("HTTPS_PROXY", "proxy.example:3128")
	if u, err := envProxy("server.example:443"); err != nil || u.String() != "http://proxy.example:3128" {
		t.Errorf("HTTPS_PROXY: %v, %v", u, err)
	}
	t.Setenv("HTTPS_PROXY", "ftp://proxy.example")
	if _, err := envProxy("server.example:443"); err == nil || !strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Errorf("bad HTTPS_PROXY: %v", err)
	}
}
