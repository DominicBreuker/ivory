//go:build ivory

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DominicBreuker/ivory/tlsutil"
)

const reverseUsage = `usage: ivory reverse [flags] -backend host:port

Accepts TLS connections with Brainpool certificates and key exchange on
-listen and forwards the plain text of each one to -backend, so that a
server without Brainpool support (any language, any TCP protocol) can
serve TLS clients of the TI. Each connection's handshake, the client's
certificate and its check are reported.

The backend leg is not encrypted: -backend accepts loopback addresses
only, unless -allow-remote is given. -listen is loopback by default;
give it another address (such as :8443) to accept TI clients from the
network. With -client-auth request or require, client certificates must
pass the check against -env, -tsl or -ca, or the handshake fails; the
backend can't see who connected.

`

// reverseOptions are what each connection of reverse needs.
type reverseOptions struct {
	cfg      *tls.Config
	certs    []tls.Certificate
	ts       *trustSpace
	backend  string
	timeout  time.Duration
	fallback bool
}

func runReverse(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("reverse", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		tf                    tlsFlags
		trust                 trustFlags
		ids                   identityFlags
		dial                  dialer
		listenAddr, backend   string
		auth, names, keyLog   string
		allowRemote           bool
		timeout               time.Duration
		jsonOut, trace, hexOn bool
	)
	tf.register(fs)
	trust.register(fs, false)
	ids.register(fs, "server")
	dial.registerDownloads(fs)
	fs.StringVar(&listenAddr, "listen", "localhost:8443", "`address` for the TLS connections (:8443 for all interfaces)")
	fs.StringVar(&backend, "backend", "", "plain-text server (`host:port`) that gets each connection's data; required")
	fs.BoolVar(&allowRemote, "allow-remote", false, "allow a -backend that is not a loopback address (the backend leg is plain text)")
	fs.StringVar(&auth, "client-auth", "none", "client certificate: none, request (checked if sent) or require; request and require need -env, -tsl or -ca")
	fs.StringVar(&names, "name", "localhost,127.0.0.1", "comma-separated DNS names and IP addresses of the generated identities (without -cert)")
	fs.StringVar(&keyLog, "keylog", "", "append TLS secrets to this `file` (NSS key log format, for Wireshark)")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "handshake and backend connection timeout")
	fs.BoolVar(&jsonOut, "json", false, "print one JSON object per event")
	fs.BoolVar(&trace, "trace", false, "print every TLS record and decoded handshake message")
	fs.BoolVar(&hexOn, "hex", false, "with -trace, add a hex dump of every record")
	fs.Usage = func() {
		fmt.Fprint(stderr, reverseUsage)
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\n"+profileHelp)
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 || backend == "" {
		fs.Usage()
		return errUsage
	}
	if err := checkBackend(backend, allowRemote); err != nil {
		return err
	}
	var clientAuth tls.ClientAuthType
	switch auth {
	case "none":
		clientAuth = tls.NoClientCert
	case "request":
		clientAuth = tls.RequestClientCert
	case "require":
		clientAuth = tls.RequireAnyClientCert
	default:
		return fmt.Errorf("-client-auth: want none, request or require, not %q", auth)
	}
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "ivory: "+format+"\n", a...) }
	trust.client = dial.httpClient()
	ts, err := trust.load(context.Background(), logf)
	if err != nil {
		return err
	}
	if clientAuth != tls.NoClientCert && ts == nil {
		return fmt.Errorf("-client-auth %s needs -env, -tsl or -ca to check client certificates", auth)
	}
	if ts != nil && ts.checker != nil {
		// As in tunnel and proxy: reuse good OCSP answers for the
		// specification's default grace period (TUC_PKI_006).
		ts.checker.GracePeriod = 10 * time.Minute
	}
	certs, err := ids.load()
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		if certs, err = generateIdentities(strings.Split(names, ",")); err != nil {
			return err
		}
		logf("serving generated self-signed identities (not trusted by anyone)")
	}
	for _, c := range certs {
		info := describeDER(c.Certificate[0])
		logf("identity %s, %s, sha256 %s", info.Subject, info.Key, info.SHA256)
	}
	cfg, err := tf.config()
	if err != nil {
		return err
	}
	cfg.GetCertificate = tlsutil.GetCertificate(certs)
	cfg.ClientAuth = clientAuth
	// Each handshake checks the client certificate again; no resumption.
	cfg.SessionTicketsDisabled = true
	if keyLog != "" {
		kf, err := os.OpenFile(keyLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer kf.Close()
		cfg.KeyLogWriter = kf
	}
	o := &reverseOptions{cfg: cfg, certs: certs, ts: ts, backend: backend, timeout: timeout,
		fallback: cfg.MinVersion <= tls.VersionTLS12 && cfg.MaxVersion >= tls.VersionTLS13}
	s := &sidecar{profile: tf.profile, timeout: timeout, trace: trace, hex: hexOn, jsonOut: jsonOut, out: stdout}

	ln, err := listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	check := "none"
	if clientAuth != tls.NoClientCert {
		check = auth
	}
	logf("reverse from %s to %s, profile %s, client certificates: %s", ln.Addr(), backend, tf.profile, check)
	if w := exposureWarning(listenAddr, backend, clientAuth); w != "" {
		logf("%s", w)
	}
	interrupted, stop := closeOnSignal(ln, logf)
	defer stop()
	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if interrupted() {
				return nil
			}
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.reverse(c, o)
		}()
	}
}

// exposureWarning returns a warning when reverse listens on an address
// other than a loopback address and asks for no client certificate:
// then anyone who can reach the port reaches the backend, which may
// trust its loopback callers.
func exposureWarning(listenAddr, backend string, clientAuth tls.ClientAuthType) string {
	if clientAuth != tls.NoClientCert {
		return ""
	}
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("warning: -listen %s is not a loopback address and -client-auth is none: "+
		"anyone who can reach it reaches %s without a client certificate", listenAddr, backend)
}

// checkBackend refuses a backend other than a loopback address unless
// remote is set: the backend leg is plain text.
func checkBackend(addr string, remote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-backend: %v", err)
	}
	if remote {
		return nil
	}
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("-backend %s: the backend leg is not encrypted, so it must be a loopback address "+
		"(localhost, 127.0.0.1, [::1]); add -allow-remote to forward to another host", addr)
}

// reverse accepts the TLS connection c, checks the client certificate and
// forwards the plain text to the backend.
func (s *sidecar) reverse(c net.Conn, o *reverseOptions) {
	defer c.Close()
	id := s.nextID.Add(1)
	ev := &sidecarEvent{Event: "accept", Connection: id, Client: c.RemoteAddr().String(), Upstream: o.backend}
	var live io.Writer
	if s.trace && !s.jsonOut {
		live = &lineWriter{s: s, prefix: fmt.Sprintf("[%d] ", id)}
	}
	hl := newHandshakeLog(live, s.hex, s.trace && s.jsonOut)
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	// A configuration per connection, so that the check reports into
	// this connection's event, also for the TLS 1.2 fallback.
	cfg := o.cfg.Clone()
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return nil // ClientAuth decides whether that's fine
		}
		leaf := cs.PeerCertificates[0]
		ci := describe(leaf)
		ev.PeerCertificate = &ci
		if o.ts == nil {
			return nil
		}
		ev.TICheck = o.ts.check(ctx, leaf)
		if ev.TICheck.Result != "ok" {
			return fmt.Errorf("TI check of the client certificate failed: %s", ev.TICheck.Error)
		}
		return nil
	}
	if o.fallback {
		cfg.GetConfigForClient = tlsutil.TLS12Fallback(cfg, o.certs)
	}
	start := time.Now()
	conn := tls.Server(&tracedConn{Conn: c, log: hl, client: false}, cfg)
	c.SetDeadline(time.Now().Add(o.timeout))
	err := conn.HandshakeContext(ctx)
	ev.Handshake = &handshakeInfo{OK: err == nil, Duration: time.Since(start).Seconds()}
	var state *tls.ConnectionState
	if err == nil {
		cs := conn.ConnectionState()
		state = &cs
	} else {
		ev.Handshake.Error = err.Error()
	}
	ev.Handshake.fill(state, hl, dirS2C)
	fail := func(err error) {
		if ev.Error == "" {
			ev.Error = err.Error()
		}
		if s.trace && s.jsonOut {
			ev.Trace = hl.trace()
		}
		s.emit(ev)
	}
	if err != nil {
		fail(err)
		return
	}
	c.SetDeadline(time.Time{})
	b, err := (&net.Dialer{Timeout: o.timeout}).DialContext(ctx, "tcp", o.backend)
	if err != nil {
		fail(fmt.Errorf("backend: %w", err))
		conn.Close()
		return
	}
	defer b.Close()
	s.emit(ev)
	t := &upstream{Conn: conn, s: s, id: id, start: start, log: hl}
	defer t.Close()
	pipe(b, t)
}
