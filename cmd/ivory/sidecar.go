//go:build ivory

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const tunnelUsage = `usage: ivory tunnel [flags] host[:port]

Accepts plain TCP connections on -listen and forwards each one over a new
TLS connection to host:port (default port 443), so that tools without
Brainpool support reach Brainpool TLS servers. Each connection's
handshake and the check of the server certificate are reported.

The local side is not encrypted: -listen accepts loopback addresses only,
unless -allow-remote is given.

`

const proxyUsage = `usage: ivory proxy [flags]

An HTTP proxy that does the TLS itself: a client sends a plain HTTP
request for http://host[:port]/path through it, and the proxy sends it
over TLS to host:port (default port 443), for example

  curl -x http://localhost:8080 http://host/path

Only targets that match -allow are forwarded; CONNECT is refused, since
the client would do the TLS itself. Each upstream connection and each
request are reported.

The local side is not encrypted: -listen accepts loopback addresses only,
unless -allow-remote is given.

`

// sidecarFlags are the flags of tunnel and proxy.
type sidecarFlags struct {
	tf                  tlsFlags
	trust               trustFlags
	ids                 identityFlags
	dial                dialer
	listen, verify      string
	keyLog              string
	allowRemote         bool
	timeout             time.Duration
	jsonOut, trace, hex bool
}

func (f *sidecarFlags) register(fs *flag.FlagSet, listen string) {
	f.tf.register(fs)
	f.trust.register(fs, true)
	f.ids.register(fs, "client")
	f.dial.register(fs)
	fs.StringVar(&f.listen, "listen", listen, "local `address` for plain-text connections")
	fs.BoolVar(&f.allowRemote, "allow-remote", false, "allow a -listen address that is not a loopback address (the local side is plain text)")
	fs.StringVar(&f.verify, "verify", "auto", "server certificate check: ti (against -env, -tsl or -ca), webpki (system roots and the server name), "+
		"none, or auto (ti with -env, -tsl or -ca, else webpki)")
	fs.StringVar(&f.keyLog, "keylog", "", "append TLS secrets to this `file` (NSS key log format, for Wireshark)")
	fs.DurationVar(&f.timeout, "timeout", 10*time.Second, "connection and handshake timeout for each upstream connection")
	fs.BoolVar(&f.jsonOut, "json", false, "print one JSON object per event")
	fs.BoolVar(&f.trace, "trace", false, "print every TLS record and decoded handshake message of the upstream connections")
	fs.BoolVar(&f.hex, "hex", false, "with -trace, add a hex dump of every record")
}

// checkListen refuses a listen address other than a loopback address
// unless remote is set: the sidecar's local side is plain text.
func checkListen(addr string, remote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-listen: %v", err)
	}
	if remote {
		return nil
	}
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("-listen %s: the local side is not encrypted, so it listens only on loopback addresses "+
		"(localhost, 127.0.0.1, [::1]); add -allow-remote to accept connections from other hosts", addr)
}

// A sidecar makes the upstream TLS connections of tunnel and proxy and
// reports them.
type sidecar struct {
	cfg        *tls.Config
	ts         *trustSpace
	verify     string // ti, webpki or none
	identities []tls.Certificate
	dial       dialer
	profile    string
	timeout    time.Duration
	trace, hex bool
	jsonOut    bool

	outMu  sync.Mutex
	out    io.Writer
	nextID atomic.Int64
}

// setup parses the flags of tunnel and proxy and returns the sidecar and
// the positional arguments. logf reports progress.
func (f *sidecarFlags) setup(fs *flag.FlagSet, args []string, stdout io.Writer, logf func(string, ...any)) (*sidecar, []string, func(), error) {
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := checkListen(f.listen, f.allowRemote); err != nil {
		return nil, nil, nil, err
	}
	if err := f.trust.guard(); err != nil {
		return nil, nil, nil, err
	}
	f.trust.client = f.dial.httpClient()
	ts, err := f.trust.load(context.Background(), logf)
	if err != nil {
		return nil, nil, nil, err
	}
	s := &sidecar{ts: ts, dial: f.dial, profile: f.tf.profile, timeout: f.timeout,
		trace: f.trace, hex: f.hex, jsonOut: f.jsonOut, out: stdout}
	switch f.verify {
	case "auto":
		s.verify = "webpki"
		if ts != nil {
			s.verify = "ti"
		}
	case "ti":
		if ts == nil {
			return nil, nil, nil, errors.New("-verify ti needs -env, -tsl or -ca")
		}
		s.verify = "ti"
	case "webpki", "none":
		s.verify = f.verify
	default:
		return nil, nil, nil, fmt.Errorf("-verify: want auto, ti, webpki or none, not %q", f.verify)
	}
	if s.verify == "none" {
		logf("warning: -verify none: the server certificate is not checked; anyone on the path can read and change the traffic")
	}
	if ts != nil && ts.checker != nil {
		// Reuse a good OCSP answer for the 10 minutes of the
		// specification's default grace period (TUC_PKI_006), rather
		// than asking for every connection.
		ts.checker.GracePeriod = 10 * time.Minute
	}
	if s.identities, err = f.ids.load(); err != nil {
		return nil, nil, nil, err
	}
	if s.cfg, err = f.tf.config(); err != nil {
		return nil, nil, nil, err
	}
	// The certificate is checked in VerifyConnection, the TI way or
	// against the system roots; crypto/x509 can't verify Brainpool
	// chains.
	s.cfg.InsecureSkipVerify = true
	s.cfg.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	s.cfg.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		for i := range s.identities {
			if cri.SupportsCertificate(&s.identities[i]) == nil {
				return &s.identities[i], nil
			}
		}
		if len(s.identities) > 0 {
			return &s.identities[0], nil
		}
		return &tls.Certificate{}, nil
	}
	done := func() {}
	if f.keyLog != "" {
		kf, err := os.OpenFile(f.keyLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, nil, err
		}
		s.cfg.KeyLogWriter = kf
		done = func() { kf.Close() }
	}
	return s, pos, done, nil
}

// A sidecarEvent is one line of the report: an upstream connection made
// or refused, a request forwarded, a connection closed.
type sidecarEvent struct {
	Time       string `json:"time"`
	Event      string `json:"event"` // connect, accept, request, refused, close
	Connection int64  `json:"connection,omitempty"`
	Client     string `json:"client,omitempty"`
	Upstream   string `json:"upstream,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	Proxy      string `json:"proxy,omitempty"`

	Handshake         *handshakeInfo `json:"handshake,omitempty"`
	Verify            string         `json:"verify,omitempty"`
	Server            *CertInfo      `json:"server_certificate,omitempty"`
	TICheck           *TICheck       `json:"ti_check,omitempty"`
	WebPKI            string         `json:"web_pki_check,omitempty"`
	ClientCertificate *CertInfo      `json:"client_certificate_sent,omitempty"`
	// PeerCertificate is the certificate a client presented to reverse.
	PeerCertificate *CertInfo `json:"client_certificate,omitempty"`

	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
	Status string `json:"status,omitempty"`

	BytesSent     int64        `json:"bytes_sent,omitempty"`
	BytesReceived int64        `json:"bytes_received,omitempty"`
	Duration      float64      `json:"duration_seconds,omitempty"`
	Error         string       `json:"error,omitempty"`
	Trace         []traceEvent `json:"trace,omitempty"`
}

// emit prints an event as a JSON line or a line of text.
func (s *sidecar) emit(ev *sidecarEvent) {
	ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
	s.outMu.Lock()
	defer s.outMu.Unlock()
	if s.jsonOut {
		writeJSON(s.out, ev, false)
		return
	}
	io.WriteString(s.out, ev.text())
}

func (ev *sidecarEvent) text() string {
	var b strings.Builder
	if ev.Connection != 0 {
		fmt.Fprintf(&b, "[%d] ", ev.Connection)
	}
	switch ev.Event {
	case "connect":
		fmt.Fprintf(&b, "%s", ev.Upstream)
		if ev.ServerName != "" && !strings.HasPrefix(ev.Upstream, ev.ServerName+":") {
			fmt.Fprintf(&b, " (SNI %s)", ev.ServerName)
		}
		if ev.Client != "" {
			fmt.Fprintf(&b, " for %s", ev.Client)
		}
		if ev.Proxy != "" {
			fmt.Fprintf(&b, " via proxy %s", ev.Proxy)
		}
		if h := ev.Handshake; h != nil && h.OK {
			fmt.Fprintf(&b, ": %v, %v", h.Version, h.CipherSuite)
			if h.Group != 0 {
				fmt.Fprintf(&b, ", %v", h.Group)
			}
			if h.Resumed {
				b.WriteString(", resumed")
			}
		}
		b.WriteString("\n")
		if c := ev.Server; c != nil {
			fmt.Fprintf(&b, "    server certificate %s (%s), issuer %s\n", c.Subject, c.Key, c.Issuer)
		}
		switch {
		case ev.TICheck != nil && ev.TICheck.Result == "ok":
			fmt.Fprintf(&b, "    TI check ok")
			if ev.TICheck.IssuerCA != "" {
				fmt.Fprintf(&b, ", issuer CA %s", ev.TICheck.IssuerCA)
			}
			if ev.TICheck.OCSP != "" {
				fmt.Fprintf(&b, ", OCSP %s", ev.TICheck.OCSP)
			}
			b.WriteString("\n")
		case ev.TICheck != nil:
			fmt.Fprintf(&b, "    TI check FAILED: %s\n", ev.TICheck.Error)
		case ev.WebPKI != "":
			fmt.Fprintf(&b, "    web PKI check %s\n", ev.WebPKI)
		case ev.Verify == "none":
			b.WriteString("    server certificate NOT checked (-verify none)\n")
		}
		if c := ev.ClientCertificate; c != nil {
			fmt.Fprintf(&b, "    client certificate sent %s (%s)\n", c.Subject, c.Key)
		}
		if h := ev.Handshake; h != nil && !h.OK {
			fmt.Fprintf(&b, "    handshake FAILED: %s\n", h.Error)
		} else if ev.Error != "" {
			fmt.Fprintf(&b, "    FAILED: %s\n", ev.Error)
		}
	case "request":
		fmt.Fprintf(&b, "%s %s", ev.Method, ev.URL)
		if ev.Status != "" {
			fmt.Fprintf(&b, ": %s, %d bytes", ev.Status, ev.BytesReceived)
		}
		if ev.Error != "" {
			fmt.Fprintf(&b, ": FAILED: %s", ev.Error)
		}
		b.WriteString("\n")
	case "accept":
		fmt.Fprintf(&b, "%s", ev.Client)
		if h := ev.Handshake; h != nil && h.OK {
			fmt.Fprintf(&b, ": %v, %v", h.Version, h.CipherSuite)
			if h.Group != 0 {
				fmt.Fprintf(&b, ", %v", h.Group)
			}
		}
		if ev.Upstream != "" {
			fmt.Fprintf(&b, ", to %s", ev.Upstream)
		}
		b.WriteString("\n")
		if c := ev.PeerCertificate; c != nil {
			fmt.Fprintf(&b, "    client certificate %s (%s), issuer %s\n", c.Subject, c.Key, c.Issuer)
		} else if h := ev.Handshake; h != nil && h.OK {
			b.WriteString("    no client certificate\n")
		}
		switch {
		case ev.TICheck != nil && ev.TICheck.Result == "ok":
			fmt.Fprintf(&b, "    TI check ok")
			if ev.TICheck.IssuerCA != "" {
				fmt.Fprintf(&b, ", issuer CA %s", ev.TICheck.IssuerCA)
			}
			if ev.TICheck.OCSP != "" {
				fmt.Fprintf(&b, ", OCSP %s", ev.TICheck.OCSP)
			}
			b.WriteString("\n")
		case ev.TICheck != nil:
			fmt.Fprintf(&b, "    TI check FAILED: %s\n", ev.TICheck.Error)
		}
		if h := ev.Handshake; h != nil && !h.OK {
			fmt.Fprintf(&b, "    handshake FAILED: %s\n", h.Error)
		} else if ev.Error != "" {
			fmt.Fprintf(&b, "    FAILED: %s\n", ev.Error)
		}
	case "refused":
		fmt.Fprintf(&b, "refused %s %s for %s: %s\n", ev.Method, ev.URL, ev.Client, ev.Error)
	case "close":
		fmt.Fprintf(&b, "closed after %.3f s: %d bytes sent, %d received", ev.Duration, ev.BytesSent, ev.BytesReceived)
		if ev.Error != "" {
			fmt.Fprintf(&b, " (%s)", ev.Error)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// lineWriter writes whole lines to the sidecar's output, each with a
// prefix, so that the traces of concurrent connections stay readable.
type lineWriter struct {
	s      *sidecar
	prefix string
	buf    []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		w.s.outMu.Lock()
		io.WriteString(w.s.out, w.prefix)
		w.s.out.Write(w.buf[:i+1])
		w.s.outMu.Unlock()
		w.buf = w.buf[i+1:]
	}
}

// upstream is a TLS connection to the target that counts the plaintext
// bytes and reports when it closes.
type upstream struct {
	*tls.Conn
	s          *sidecar
	id         int64
	start      time.Time
	log        *handshakeLog
	sent, recv atomic.Int64
	closeOnce  sync.Once
	err        atomic.Value // first error other than EOF, as string
}

func (u *upstream) Read(b []byte) (int, error) {
	n, err := u.Conn.Read(b)
	u.recv.Add(int64(n))
	if err != nil && err != io.EOF {
		u.err.CompareAndSwap(nil, err.Error())
	}
	return n, err
}

func (u *upstream) Write(b []byte) (int, error) {
	n, err := u.Conn.Write(b)
	u.sent.Add(int64(n))
	if err != nil {
		u.err.CompareAndSwap(nil, err.Error())
	}
	return n, err
}

func (u *upstream) Close() error {
	err := u.Conn.Close()
	u.closeOnce.Do(func() {
		ev := &sidecarEvent{Event: "close", Connection: u.id, Duration: time.Since(u.start).Seconds(),
			BytesSent: u.sent.Load(), BytesReceived: u.recv.Load()}
		if e, ok := u.err.Load().(string); ok && !strings.Contains(e, "use of closed network connection") {
			ev.Error = e
		}
		if u.s.trace && u.s.jsonOut {
			ev.Trace = u.log.trace()
		}
		u.s.emit(ev)
	})
	return err
}

// connect opens a TLS connection to addr and checks the server's
// certificate. client is the local peer, for the report.
func (s *sidecar) connect(ctx context.Context, client, addr, serverName string) (*upstream, error) {
	id := s.nextID.Add(1)
	ev := &sidecarEvent{Event: "connect", Connection: id, Client: client, Upstream: addr,
		ServerName: serverName, Proxy: s.dial.describe(addr), Verify: s.verify}
	var live io.Writer
	if s.trace && !s.jsonOut {
		live = &lineWriter{s: s, prefix: fmt.Sprintf("[%d] ", id)}
	}
	hl := newHandshakeLog(live, s.hex, s.trace && s.jsonOut)
	fail := func(err error) (*upstream, error) {
		ev.Error = err.Error()
		if s.trace && s.jsonOut {
			ev.Trace = hl.trace()
		}
		s.emit(ev)
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	dial := s.dial
	dial.timeout = s.timeout
	start := time.Now()
	raw, err := dial.dial(ctx, addr)
	if err != nil {
		return fail(err)
	}
	cfg := s.cfg.Clone()
	cfg.ServerName = serverName
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		return s.check(ctx, cs, serverName, ev)
	}
	conn := tls.Client(&tracedConn{Conn: raw, log: hl, client: true}, cfg)
	raw.SetDeadline(time.Now().Add(s.timeout))
	err = conn.HandshakeContext(ctx)
	ev.Handshake = &handshakeInfo{OK: err == nil, Duration: time.Since(start).Seconds()}
	var state *tls.ConnectionState
	if err == nil {
		cs := conn.ConnectionState()
		state = &cs
		if len(cs.LocalCertificate) > 0 {
			ci := describeDER(cs.LocalCertificate[0])
			ev.ClientCertificate = &ci
		}
	} else {
		ev.Handshake.Error = err.Error()
	}
	ev.Handshake.fill(state, hl, dirC2S)
	if err != nil {
		raw.Close()
		if ev.Error == "" {
			ev.Error = err.Error()
		}
		return fail(err)
	}
	raw.SetDeadline(time.Time{})
	s.emit(ev)
	return &upstream{Conn: conn, s: s, id: id, start: start, log: hl}, nil
}

// check runs in VerifyConnection, so that a server certificate that fails
// fails the handshake, before a client certificate is sent in TLS 1.2.
func (s *sidecar) check(ctx context.Context, cs tls.ConnectionState, serverName string, ev *sidecarEvent) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("the server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	ci := describe(leaf)
	ev.Server = &ci
	switch s.verify {
	case "ti":
		ev.TICheck = s.ts.check(ctx, leaf)
		if ev.TICheck.Result != "ok" {
			return fmt.Errorf("TI check of the server certificate failed: %s", ev.TICheck.Error)
		}
	case "webpki":
		var ders [][]byte
		for _, c := range cs.PeerCertificates {
			ders = append(ders, c.Raw)
		}
		if serverName == "" {
			ev.WebPKI = "FAILED: no server name (use -servername, or -verify ti with -env, -tsl or -ca)"
		} else {
			ev.WebPKI = webPKICheck(ders, serverName)
		}
		if ev.WebPKI != "ok" {
			return fmt.Errorf("web PKI check of the server certificate %s", ev.WebPKI)
		}
	}
	return nil
}

// serverNameFor returns the SNI for a target host: the host, unless it is
// an IP address.
func serverNameFor(addr string) string {
	host, _, _ := net.SplitHostPort(addr)
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func runTunnel(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		f          sidecarFlags
		serverName string
	)
	f.register(fs, "localhost:8443")
	fs.StringVar(&serverName, "servername", "", "server name for SNI and the web PKI check (default: the host, unless it is an IP address)")
	fs.Usage = func() {
		fmt.Fprint(stderr, tunnelUsage)
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\n"+profileHelp)
	}
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "ivory: "+format+"\n", a...) }
	s, pos, done, err := f.setup(fs, args, stdout, logf)
	if err != nil {
		return err
	}
	defer done()
	if len(pos) != 1 {
		fs.Usage()
		return errUsage
	}
	addr := withPort(pos[0], "443")
	if serverName == "" {
		serverName = serverNameFor(addr)
	}
	ln, err := listen("tcp", f.listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	logf("tunnel from %s to %s, profile %s, server certificate check: %s", ln.Addr(), addr, s.profile, s.verify)
	interrupted, stop := closeOnSignal(ln, logf)
	defer stop()
	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if interrupted() {
				return nil // without waiting for open connections
			}
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.tunnel(c, addr, serverName)
		}()
	}
}

// closeOnSignal closes ln on SIGINT or SIGTERM. interrupted reports
// whether that happened; stop releases the signals.
func closeOnSignal(ln net.Listener, logf func(string, ...any)) (interrupted func() bool, stop func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	var got atomic.Bool
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			got.Store(true)
			logf("stopping")
			ln.Close()
		case <-done:
		}
	}()
	return got.Load, func() { signal.Stop(sig); close(done) }
}

// tunnel forwards the local connection c over a new TLS connection.
func (s *sidecar) tunnel(c net.Conn, addr, serverName string) {
	defer c.Close()
	up, err := s.connect(context.Background(), c.RemoteAddr().String(), addr, serverName)
	if err != nil {
		return
	}
	defer up.Close()
	pipe(c, up)
}

// pipe copies between the plain-text connection c and the TLS connection
// t until both directions end. When one side is done sending, the other
// learns it (close_notify or a TCP half-close) and may still answer.
func pipe(c net.Conn, t *upstream) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(t, c); err == nil {
			t.CloseWrite()
		} else {
			t.Conn.Close()
		}
	}()
	_, err := io.Copy(c, t)
	if cw, ok := c.(interface{ CloseWrite() error }); ok && err == nil {
		cw.CloseWrite()
	} else {
		c.Close()
	}
	wg.Wait()
}

func runProxy(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		f     sidecarFlags
		allow listFlag
	)
	f.register(fs, "localhost:8080")
	fs.Var(&allow, "allow", "target the proxy may connect to: host, host:port, *.domain or *.domain:port "+
		"(no port: any port), or * for any; repeatable or comma-separated; required")
	fs.Usage = func() {
		fmt.Fprint(stderr, proxyUsage)
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\n"+profileHelp)
	}
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "ivory: "+format+"\n", a...) }
	s, pos, done, err := f.setup(fs, args, stdout, logf)
	if err != nil {
		return err
	}
	defer done()
	if len(pos) != 0 {
		fs.Usage()
		return errUsage
	}
	rules, err := parseAllow(allow)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return errors.New("proxy: name the targets it may connect to with -allow (for example -allow '*.example.org:443'), " +
			"so that it can't be used as an open proxy; -allow '*' allows every target")
	}
	if f.tf.alpn == "" {
		// The upstream connections carry HTTP/1.1.
		s.cfg.NextProtos = []string{"http/1.1"}
	}
	ln, err := listen("tcp", f.listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	logf("HTTP proxy on %s for %s, profile %s, server certificate check: %s", ln.Addr(), rules, s.profile, s.verify)
	p := &httpProxy{s: s, allow: rules}
	p.transport = &http.Transport{
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			c, err := s.connect(ctx, "", addr, serverNameFor(addr))
			if err != nil {
				return nil, err // reported already
			}
			return c, nil
		},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	defer p.transport.CloseIdleConnections()
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second, ErrorLog: nullLogger()}
	interrupted, stop := closeOnSignal(ln, logf)
	defer stop()
	err = srv.Serve(ln)
	if interrupted() {
		err = nil
	}
	// Let the requests in progress finish and report.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	return err
}

// httpProxy forwards plain HTTP requests in absolute form over TLS.
type httpProxy struct {
	s         *sidecar
	allow     allowList
	transport *http.Transport
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	refuse := func(code int, msg string) {
		p.s.emit(&sidecarEvent{Event: "refused", Client: r.RemoteAddr, Method: r.Method, URL: r.RequestURI, Error: msg})
		http.Error(w, "ivory proxy: "+msg, code)
	}
	example := "curl -x http://localhost:8080 http://host/path"
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		example = "curl -x http://" + a.String() + " http://host/path"
	}
	switch {
	case r.Method == http.MethodConnect:
		refuse(http.StatusMethodNotAllowed, "CONNECT is not supported: the proxy does the TLS itself, so ask it for http:// URLs ("+example+")")
		return
	case !r.URL.IsAbs() || r.URL.Host == "":
		refuse(http.StatusBadRequest, "use this as an HTTP proxy, with an absolute URL in the request ("+example+")")
		return
	case r.URL.Scheme != "http":
		refuse(http.StatusBadRequest, "only http:// URLs: the proxy turns them into TLS connections")
		return
	}
	target := withPort(r.URL.Host, "443")
	if !p.allow.allows(target) {
		refuse(http.StatusForbidden, target+" is not an allowed target (-allow)")
		return
	}
	ev := &sidecarEvent{Event: "request", Client: r.RemoteAddr, Method: r.Method, URL: r.URL.String(), Upstream: target}
	ctx := httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if u, ok := info.Conn.(*upstream); ok {
				ev.Connection = u.id
			}
		},
	})
	cw := &countingWriter{ResponseWriter: w}
	rp := &httputil.ReverseProxy{
		Transport: p.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = target
			// The URL's authority, not a Host header, names the target
			// of a request in absolute form (RFC 9112, Section 3.2.2).
			pr.Out.Host = strings.TrimSuffix(target, ":443")
		},
		ModifyResponse: func(resp *http.Response) error {
			ev.Status = resp.Status
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			ev.Error = err.Error()
			http.Error(w, "ivory proxy: "+err.Error(), http.StatusBadGateway)
		},
		ErrorLog: nullLogger(),
	}
	rp.ServeHTTP(cw, r.WithContext(ctx))
	ev.BytesReceived = cw.n
	p.s.emit(ev)
}

// countingWriter counts the body bytes of a response.
type countingWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// An allowRule matches targets: a host or a domain's subdomains
// (*.domain), on one port or on any.
type allowRule struct {
	host   string // lower case; "*" any; ".domain" for *.domain
	port   string // "" any
	source string
}

type allowList []allowRule

func (l allowList) String() string {
	var s []string
	for _, r := range l {
		s = append(s, r.source)
	}
	return strings.Join(s, ", ")
}

func parseAllow(items []string) (allowList, error) {
	var out allowList
	for _, item := range items {
		for _, src := range strings.Split(item, ",") {
			src = strings.TrimSpace(src)
			if src == "" {
				continue
			}
			r := allowRule{host: strings.ToLower(src), source: src}
			if h, p, err := net.SplitHostPort(src); err == nil {
				if _, err := net.LookupPort("tcp", p); err != nil || p == "" {
					return nil, fmt.Errorf("-allow %q: bad port", src)
				}
				r.host, r.port = strings.ToLower(h), p
			} else {
				r.host = strings.ToLower(strings.Trim(src, "[]"))
				if strings.Contains(r.host, ":") && net.ParseIP(r.host) == nil {
					return nil, fmt.Errorf("-allow %q: want host, host:port, *.domain, *.domain:port or *", src)
				}
			}
			switch {
			case r.host == "*":
			case strings.HasPrefix(r.host, "*."):
				r.host = r.host[1:]
				if len(r.host) < 2 || strings.Contains(r.host[1:], "*") {
					return nil, fmt.Errorf("-allow %q: want *.domain", src)
				}
			case r.host == "" || strings.Contains(r.host, "*"):
				return nil, fmt.Errorf("-allow %q: want host, host:port, *.domain, *.domain:port or *", src)
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// allows reports whether a rule matches the target host:port.
func (l allowList) allows(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, r := range l {
		if r.port != "" && r.port != port {
			continue
		}
		switch {
		case r.host == "*",
			r.host == host,
			strings.HasPrefix(r.host, ".") && strings.HasSuffix(host, r.host):
			return true
		}
	}
	return false
}

// nullLogger discards the log lines of net/http: the events report what
// matters.
func nullLogger() *log.Logger { return log.New(io.Discard, "", 0) }
