//go:build ivory

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/cmd/ivory/internal/wire"
	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
	"github.com/DominicBreuker/ivory/x509util"
)

const probeUsage = `usage: ivory probe [flags] host[:port]

Finds out what a TLS server supports. A single handshake shows only what
both sides agreed on, so the probe sends many ClientHellos, each offering
a narrower set of options, and records the server's answers: protocol
versions, cipher suites and their order, groups for TLS 1.2 and 1.3,
signature schemes, extensions, fallback protection, the certificates it
presents and what it asks of clients. Most probes stop after the
server's first flight, so no client certificate is needed.

Each probe is a TCP connection; -delay spaces them out. Probe only
servers you are allowed to test.

`

// Probe lists. TLS 1.2 groups are those a ServerKeyExchange can name;
// TLS 1.3 groups those a HelloRetryRequest can name.
var (
	probeGroups12 = []wire.Group{0x0017, 0x0018, 0x0019, 0x001d, 0x001e, 0x001a, 0x001b, 0x001c}
	probeGroups13 = []wire.Group{
		0x0017, 0x0018, 0x0019, 0x001d, 0x001e,
		0x001f, 0x0020, 0x0021, // Brainpool, RFC 8734
		0x001a, 0x001b, 0x001c, // Brainpool TLS 1.2 code points
		0x0100, 0x0101,
		0x11ec, 0x11eb, 0x11ed, 0x0201, 0x0202,
	}
	probeSchemes12 = []wire.SignatureScheme{
		0x0403, 0x0503, 0x0603,
		0x0804, 0x0805, 0x0806,
		0x0401, 0x0501, 0x0601,
		0x0809, 0x080a, 0x080b,
		0x0807, 0x0808,
		0x0203, 0x0201,
		0x081a, 0x081b, 0x081c,
	}
	probeSchemes13 = []wire.SignatureScheme{
		0x0403, 0x0503, 0x0603,
		0x081a, 0x081b, 0x081c,
		0x0804, 0x0805, 0x0806,
		0x0809, 0x080a, 0x080b,
		0x0807, 0x0808,
	}
	allSchemes = slices.Concat(probeSchemes12, []wire.SignatureScheme{0x0904, 0x0905, 0x0906})
)

// goGroups13 are the TLS 1.3 groups that crypto/tls or ivory implement,
// for the full handshakes.
var goGroups13 = []wire.Group{0x0017, 0x0018, 0x0019, 0x001d, 0x11ec, 0x11eb, 0x11ed, 0x001f, 0x0020, 0x0021}

type probeReport struct {
	Address    string          `json:"address"`
	ServerName string          `json:"server_name,omitempty"`
	Proxy      string          `json:"proxy,omitempty"`
	Started    time.Time       `json:"started"`
	Duration   float64         `json:"duration_seconds"`
	Probes     int             `json:"probes"`
	Versions   []versionResult `json:"versions,omitempty"`
	// Suites are the cipher suites per version, in the order the server
	// chose them when offered all that remained.
	Suites     map[string]*suiteResult `json:"cipher_suites,omitempty"`
	Groups12   *groupResult            `json:"groups_tls12,omitempty"`
	Groups13   *groupResult            `json:"groups_tls13,omitempty"`
	Schemes12  []schemeResult          `json:"signature_schemes_tls12,omitempty"`
	Schemes13  []schemeResult          `json:"signature_schemes_tls13,omitempty"`
	Extensions *extensionResult        `json:"extensions,omitempty"`
	Fallback   string                  `json:"fallback_scsv,omitempty"`
	ClientAuth []clientAuthResult      `json:"client_auth,omitempty"`
	Certs      []probeCert             `json:"certificates,omitempty"`
	TI         []string                `json:"ti_observations,omitempty"`
	Notes      []string                `json:"notes,omitempty"`
}

type versionResult struct {
	Version   wire.Version `json:"version"`
	Supported bool         `json:"supported"`
	Answer    string       `json:"answer"`
}

type suiteResult struct {
	Suites     []wire.CipherSuite `json:"suites"`
	Preference string             `json:"preference,omitempty"`
}

type groupResult struct {
	Results    []itemResult `json:"results"`
	Preference string       `json:"preference,omitempty"`
}

type itemResult struct {
	Group     wire.Group `json:"group"`
	Supported bool       `json:"supported"`
	Answer    string     `json:"answer"`
}

type schemeResult struct {
	Scheme      wire.SignatureScheme `json:"scheme"`
	Supported   bool                 `json:"supported"`
	Answer      string               `json:"answer"`
	Certificate string               `json:"certificate,omitempty"`
}

type extensionResult struct {
	ExtendedMasterSecret bool   `json:"extended_master_secret"`
	SecureRenegotiation  bool   `json:"secure_renegotiation"`
	SessionTicket        bool   `json:"session_ticket"`
	SessionID            bool   `json:"session_id"`
	OCSPStapling         bool   `json:"ocsp_stapling"`
	SCT                  bool   `json:"signed_certificate_timestamp"`
	ALPN                 string `json:"alpn,omitempty"`
	EncryptThenMAC       string `json:"encrypt_then_mac,omitempty"`
	Compression          string `json:"compression"`
	Answer               string `json:"answer,omitempty"`
}

type clientAuthResult struct {
	Version wire.Version `json:"version"`
	certRequestInfo
}

type probeCert struct {
	chainReport
	SeenWith []string `json:"seen_with"`
}

// A flight is what a server answered to a ClientHello, up to its
// ServerHelloDone, its (TLS 1.3) ServerHello or HelloRetryRequest, an
// alert, or the end of the connection.
type flight struct {
	sh      *wire.ServerHello
	certs   [][]byte
	ske     *wire.ServerKeyExchange
	cr      *wire.CertificateRequest
	stapled bool
	alert   *wire.Alert
	err     error
}

func (f *flight) answer() string {
	switch {
	case f.alert != nil:
		return "alert " + f.alert.String()
	case f.sh != nil && f.sh.HelloRetryRequest:
		return fmt.Sprintf("HelloRetryRequest %v %s %s", f.sh.Negotiated(), f.sh.CipherSuite.Name(), f.sh.KeyShare.Name())
	case f.sh != nil:
		s := fmt.Sprintf("ServerHello %v %s", f.sh.Negotiated(), f.sh.CipherSuite.Name())
		if f.ske != nil {
			if f.ske.Kind == "ECDHE" {
				s += " " + f.ske.Group.Name()
			} else {
				s += fmt.Sprintf(" DHE-%d", f.ske.DHBits)
			}
			if f.ske.SignatureScheme != 0 {
				s += " " + f.ske.SignatureScheme.Name()
			}
		}
		return s
	case f.err != nil:
		return "no answer: " + f.err.Error()
	}
	return "no answer"
}

// version returns the version the server chose, or 0.
func (f *flight) version() wire.Version {
	if f.sh == nil {
		return 0
	}
	return f.sh.Negotiated()
}

type prober struct {
	addr, serverName string
	timeout, delay   time.Duration
	trace            io.Writer
	dial             *dialer
	ids              []tls.Certificate
	ts               *trustSpace
	n                int
	certs            map[[32]byte]*probeCert
	certOrder        [][32]byte
	certCurves       []wire.Group
	report           *probeReport
}

func runProbe(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		trust          trustFlags
		ids            identityFlags
		dial           dialer
		serverName     string
		only           string
		timeout, delay time.Duration
		jsonOut, trace bool
	)
	trust.register(fs, true)
	ids.register(fs, "client")
	dial.register(fs)
	fs.StringVar(&serverName, "servername", "", "server name for SNI (default: the host, unless it is an IP address)")
	fs.StringVar(&only, "only", "", "comma-separated sections to run: versions, suites, groups, sigalgs, extensions, fallback (default all)")
	fs.DurationVar(&timeout, "timeout", 5*time.Second, "timeout of each probe")
	fs.DurationVar(&delay, "delay", 100*time.Millisecond, "pause between probes")
	fs.BoolVar(&jsonOut, "json", false, "print the report as JSON")
	fs.BoolVar(&trace, "trace", false, "print every probe: what it offered and what the server answered")
	fs.Usage = func() {
		fmt.Fprint(stderr, probeUsage)
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return errUsage
	}
	if err := trust.guard(); err != nil {
		return err
	}
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "ivory: "+format+"\n", a...) }
	trust.client = dial.httpClient()
	ts, err := trust.load(context.Background(), logf)
	if err != nil {
		return err
	}
	identities, err := ids.load()
	if err != nil {
		return err
	}
	addr := withPort(pos[0], "443")
	host, _, _ := net.SplitHostPort(addr)
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}
	sections := map[string]bool{}
	for _, s := range strings.Split(only, ",") {
		if s = strings.TrimSpace(s); s != "" {
			if !slices.Contains([]string{"versions", "suites", "groups", "sigalgs", "extensions", "fallback"}, s) {
				return fmt.Errorf("-only: unknown section %q", s)
			}
			sections[s] = true
		}
	}
	dial.timeout = timeout
	p := &prober{addr: addr, serverName: serverName, timeout: timeout, delay: delay, dial: &dial, ids: identities, ts: ts,
		certs: map[[32]byte]*probeCert{}}
	if trace {
		p.trace = stderr
		if !jsonOut {
			p.trace = stdout
		}
	}
	var live io.Writer
	if !jsonOut {
		live = stdout
	}
	r := p.run(sections, live)
	if jsonOut {
		return writeJSON(stdout, r, true)
	}
	return nil
}

// run probes the sections (all if empty) and prints each to live as it
// completes.
func (p *prober) run(sections map[string]bool, live io.Writer) *probeReport {
	r := &probeReport{Address: p.addr, ServerName: p.serverName, Proxy: p.dial.describe(p.addr), Started: time.Now().UTC(), Suites: map[string]*suiteResult{}}
	p.report = r
	want := func(s string) bool { return len(sections) == 0 || sections[s] }
	out := func(f func(io.Writer)) {
		if live != nil {
			f(live)
		}
	}
	out(func(w io.Writer) {
		fmt.Fprintf(w, "Probing %s", p.addr)
		if p.serverName != "" {
			fmt.Fprintf(w, " (SNI %s)", p.serverName)
		}
		if r.Proxy != "" {
			fmt.Fprintf(w, " via proxy %s", r.Proxy)
		}
		fmt.Fprintln(w)
	})

	// The versions are needed by every other section.
	p.probeVersions(r)
	out(r.printVersions)
	if !r.supports(wire.VersionTLS12) && !r.supports(wire.VersionTLS13) && !r.supports(wire.VersionTLS11) && !r.supports(wire.VersionTLS10) {
		r.Notes = append(r.Notes, "the server answered no ClientHello with a ServerHello; check the address and -servername")
	}
	for _, v := range []wire.Version{wire.VersionTLS12, wire.VersionTLS11, wire.VersionTLS10} {
		if r.supports(v) && (want("suites") || v == wire.VersionTLS12) {
			p.probeSuites(r, v)
		}
	}
	if r.supports(wire.VersionTLS13) && (want("suites") || want("groups") || want("sigalgs")) {
		p.probeSuites13(r)
	}
	if want("suites") {
		out(r.printSuites)
	}
	if want("groups") {
		if r.supports(wire.VersionTLS12) {
			p.probeGroups12(r)
		}
		if r.supports(wire.VersionTLS13) {
			p.probeGroups13(r)
		}
		out(r.printGroups)
	}
	if want("sigalgs") {
		if r.supports(wire.VersionTLS12) {
			p.probeSchemes12(r)
		}
		if r.supports(wire.VersionTLS13) {
			p.probeSchemes13(r)
		}
		out(r.printSchemes)
	}
	if want("extensions") && r.supports(wire.VersionTLS12) {
		p.probeExtensions(r)
		out(r.printExtensions)
	}
	if want("fallback") {
		p.probeFallback(r)
		out(func(w io.Writer) {
			fmt.Fprintln(w, "Fallback protection")
			kv(w, "TLS_FALLBACK_SCSV", r.Fallback)
		})
	}
	for _, k := range p.certOrder {
		r.Certs = append(r.Certs, *p.certs[k])
	}
	out(r.printCerts)
	r.TI = r.tiObservations()
	r.Probes = p.n
	r.Duration = time.Since(r.Started).Seconds()
	out(r.printSummary)
	return r
}

func (r *probeReport) supports(v wire.Version) bool {
	for _, x := range r.Versions {
		if x.Version == v {
			return x.Supported
		}
	}
	return false
}

// spec12 returns a ClientHello for TLS 1.2 or older.
func (p *prober) spec12(v wire.Version, suites []wire.CipherSuite, groups []wire.Group, schemes []wire.SignatureScheme) *wire.HelloSpec {
	h := &wire.HelloSpec{
		Version: v, RecordVersion: wire.VersionTLS10, CipherSuites: suites, ServerName: p.serverName,
		SupportedGroups: groups, ECPointFormats: groups != nil,
		ExtendedMasterSecret: true, RenegotiationInfo: true,
	}
	if v >= wire.VersionTLS12 {
		h.SignatureAlgorithms = schemes
	}
	return h
}

// spec13 returns a TLS 1.3 ClientHello with an empty key_share, which a
// server answers with a HelloRetryRequest naming its suite and group.
func (p *prober) spec13(suites []wire.CipherSuite, groups []wire.Group, schemes []wire.SignatureScheme) *wire.HelloSpec {
	return &wire.HelloSpec{
		Version: wire.VersionTLS12, RecordVersion: wire.VersionTLS10, CipherSuites: suites, ServerName: p.serverName,
		SupportedVersions: []wire.Version{wire.VersionTLS13}, SupportedGroups: groups, EmptyKeyShare: true,
		SignatureAlgorithms: schemes, PSKModes: true,
	}
}

// hello sends one ClientHello on a new connection and reads the server's
// first flight.
func (p *prober) hello(spec *wire.HelloSpec, what string) *flight {
	if p.n > 0 && p.delay > 0 {
		time.Sleep(p.delay)
	}
	p.n++
	f := p.exchange(spec)
	if p.trace != nil {
		fmt.Fprintf(p.trace, "probe %3d  %-44s -> %s\n", p.n, what, f.answer())
	}
	if f.cr != nil {
		p.noteCertRequest(f.version(), certRequestFromWire(f.cr))
	}
	return f
}

func (p *prober) exchange(spec *wire.HelloSpec) *flight {
	f := &flight{}
	conn, err := p.dial.dial(context.Background(), p.addr)
	if err != nil {
		f.err = err
		return f
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))
	if _, err := conn.Write(spec.Bytes()); err != nil {
		f.err = err
		return f
	}
	var s wire.Stream
	buf := make([]byte, 16<<10)
	for {
		n, err := conn.Read(buf)
		for _, e := range s.Feed(buf[:n]) {
			if e.Alert != nil {
				f.alert = e.Alert
				return f
			}
			if e.Encrypted || e.ChangeCipherSpec {
				return f
			}
			for _, m := range e.Messages {
				if done := f.message(m); done {
					return f
				}
			}
		}
		if s.Broken() {
			f.err = errors.New("the answer is not TLS")
			return f
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("connection closed")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				err = errors.New("timeout")
			}
			f.err = err
			return f
		}
	}
}

// message records a handshake message and reports whether the flight is
// complete.
func (f *flight) message(m wire.Message) bool {
	switch m.Type {
	case wire.TypeServerHello:
		sh, err := wire.ParseServerHello(m.Body)
		if err != nil {
			f.err = err
			return true
		}
		f.sh = sh
		return sh.HelloRetryRequest || sh.Negotiated() == wire.VersionTLS13
	case wire.TypeCertificate:
		f.certs, _ = wire.ParseCertificate(m.Body, false)
	case wire.TypeServerKeyExchange:
		f.ske, _ = wire.ParseServerKeyExchange(m.Body, f.version())
	case wire.TypeCertificateRequest:
		f.cr, _ = wire.ParseCertificateRequest(m.Body, f.version())
	case wire.TypeCertificateStatus:
		f.stapled = true
	case wire.TypeServerHelloDone:
		return true
	}
	return false
}

// seen records the certificate chain of a flight.
func (p *prober) seen(chain [][]byte, with string) {
	if len(chain) == 0 {
		return
	}
	k := sha256.Sum256(chain[0])
	pc, ok := p.certs[k]
	if !ok {
		pc = &probeCert{chainReport: *newChainReport(context.Background(), chain, p.ts)}
		p.certs[k] = pc
		p.certOrder = append(p.certOrder, k)
		if c, err := x509.ParseCertificate(chain[0]); err == nil {
			if g := curveGroup(c); g != 0 && !slices.Contains(p.certCurves, g) {
				p.certCurves = append(p.certCurves, g)
			}
		}
	}
	if !slices.Contains(pc.SeenWith, with) {
		pc.SeenWith = append(pc.SeenWith, with)
	}
}

// curveGroup returns the TLS 1.2 group of an EC certificate's curve, or 0.
func curveGroup(c *x509.Certificate) wire.Group {
	pub, err := x509util.PublicKey(c)
	if err != nil {
		return 0
	}
	switch k := pub.(type) {
	case *brainpool.PublicKey:
		switch k.Curve() {
		case brainpool.P256r1():
			return 0x001a
		case brainpool.P384r1():
			return 0x001b
		case brainpool.P512r1():
			return 0x001c
		}
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return 0x0017
		case "P-384":
			return 0x0018
		case "P-521":
			return 0x0019
		}
	}
	return 0
}

func certLabel(chain [][]byte) string {
	if len(chain) == 0 {
		return ""
	}
	info := describeDER(chain[0])
	return fmt.Sprintf("%s, %s, sha256 %s", info.Subject, info.Key, info.SHA256[:16])
}

func (p *prober) noteCertRequest(v wire.Version, cr *certRequestInfo) {
	for _, x := range p.report.ClientAuth {
		if x.Version == v {
			return
		}
	}
	p.report.ClientAuth = append(p.report.ClientAuth, clientAuthResult{Version: v, certRequestInfo: *cr})
}

func (p *prober) probeVersions(r *probeReport) {
	ssl3 := &wire.HelloSpec{Version: wire.VersionSSL30, RecordVersion: wire.VersionSSL30, CipherSuites: wire.AllSuites()}
	for _, v := range []wire.Version{wire.VersionSSL30, wire.VersionTLS10, wire.VersionTLS11, wire.VersionTLS12} {
		spec := ssl3
		if v != wire.VersionSSL30 {
			spec = p.spec12(v, wire.AllSuites(), probeGroups12, allSchemes)
		}
		f := p.hello(spec, "version "+v.String())
		res := versionResult{Version: v, Answer: f.answer(), Supported: f.sh != nil && f.version() == v}
		if res.Supported && v >= wire.VersionTLS10 {
			p.seen(f.certs, fmt.Sprintf("%v %s", v, f.sh.CipherSuite.Name()))
		}
		r.Versions = append(r.Versions, res)
	}
	f := p.hello(p.spec13(wire.TLS13Suites(), probeGroups13, allSchemes), "version TLS 1.3")
	r.Versions = append(r.Versions, versionResult{Version: wire.VersionTLS13, Answer: f.answer(), Supported: f.version() == wire.VersionTLS13})
}

// probeSuites finds the cipher suites of a TLS 1.2 or older version: offer
// all, take the server's choice out, repeat.
func (p *prober) probeSuites(r *probeReport, v wire.Version) {
	offered := wire.AllSuites()
	res := &suiteResult{}
	for len(offered) > 0 {
		f := p.hello(p.spec12(v, offered, probeGroups12, allSchemes), fmt.Sprintf("%v suites (%d offered)", v, len(offered)))
		if f.sh == nil || f.version() != v {
			break
		}
		s := f.sh.CipherSuite
		if !slices.Contains(offered, s) {
			r.Notes = append(r.Notes, fmt.Sprintf("%v: the server chose %v, which the client didn't offer", v, s))
			break
		}
		p.seen(f.certs, fmt.Sprintf("%v %s", v, s.Name()))
		res.Suites = append(res.Suites, s)
		offered = slices.DeleteFunc(offered, func(x wire.CipherSuite) bool { return x == s })
	}
	if len(res.Suites) >= 2 {
		rev := slices.Clone(res.Suites)
		slices.Reverse(rev)
		f := p.hello(p.spec12(v, rev, probeGroups12, allSchemes), fmt.Sprintf("%v suite order", v))
		res.Preference = preference(f.sh != nil, func() bool { return f.sh.CipherSuite == res.Suites[0] }, func() bool { return f.sh.CipherSuite == rev[0] })
	}
	r.Suites[v.String()] = res
}

func preference(answered bool, server, client func() bool) string {
	switch {
	case !answered:
		return "unknown"
	case server():
		return "server"
	case client():
		return "client"
	}
	return "mixed"
}

func (p *prober) probeSuites13(r *probeReport) {
	offered := wire.TLS13Suites()
	res := &suiteResult{}
	for len(offered) > 0 {
		f := p.hello(p.spec13(offered, probeGroups13, allSchemes), fmt.Sprintf("TLS 1.3 suites (%d offered)", len(offered)))
		if f.version() != wire.VersionTLS13 || !slices.Contains(offered, f.sh.CipherSuite) {
			break
		}
		res.Suites = append(res.Suites, f.sh.CipherSuite)
		offered = slices.DeleteFunc(offered, func(x wire.CipherSuite) bool { return x == f.sh.CipherSuite })
	}
	if len(res.Suites) >= 2 {
		rev := slices.Clone(res.Suites)
		slices.Reverse(rev)
		f := p.hello(p.spec13(rev, probeGroups13, allSchemes), "TLS 1.3 suite order")
		res.Preference = preference(f.version() == wire.VersionTLS13, func() bool { return f.sh.CipherSuite == res.Suites[0] }, func() bool { return f.sh.CipherSuite == rev[0] })
	}
	r.Suites[wire.VersionTLS13.String()] = res
}

// suites12 returns the TLS 1.2 suites found, or all if none were.
func (r *probeReport) suites12(filter func(wire.CipherSuite) bool) []wire.CipherSuite {
	var out []wire.CipherSuite
	if res := r.Suites[wire.VersionTLS12.String()]; res != nil {
		for _, s := range res.Suites {
			if filter == nil || filter(s) {
				out = append(out, s)
			}
		}
	}
	return out
}

func (r *probeReport) suites13() []wire.CipherSuite {
	if res := r.Suites[wire.VersionTLS13.String()]; res != nil && len(res.Suites) > 0 {
		return res.Suites
	}
	return wire.TLS13Suites()
}

func (p *prober) probeGroups12(r *probeReport) {
	suites := r.suites12(wire.CipherSuite.IsECDHE)
	if len(suites) == 0 {
		r.Notes = append(r.Notes, "TLS 1.2 groups not probed: no ECDHE cipher suite found")
		return
	}
	res := &groupResult{}
	var supported []wire.Group
	for _, g := range probeGroups12 {
		f := p.hello(p.spec12(wire.VersionTLS12, suites, []wire.Group{g}, allSchemes), "TLS 1.2 group "+g.Name())
		ir := itemResult{Group: g, Answer: f.answer(), Supported: f.ske != nil && f.ske.Group == g}
		if !ir.Supported && f.sh == nil {
			// A server whose ECDSA certificate is on another curve may
			// refuse a client that doesn't list that curve (RFC 8422,
			// Section 5.1): offer it too, after g.
			var extra []wire.Group
			for _, c := range p.certCurves {
				if c != g {
					extra = append(extra, c)
				}
			}
			if len(extra) > 0 {
				f2 := p.hello(p.spec12(wire.VersionTLS12, suites, append([]wire.Group{g}, extra...), allSchemes), "TLS 1.2 group "+g.Name()+" + cert curve")
				if f2.ske != nil && f2.ske.Group == g {
					ir.Supported = true
					ir.Answer = f2.answer() + " (only with the certificate's curve offered too)"
				}
			}
		}
		if ir.Supported {
			supported = append(supported, g)
		}
		res.Results = append(res.Results, ir)
	}
	if len(supported) >= 2 {
		rev := slices.Clone(supported)
		slices.Reverse(rev)
		f1 := p.hello(p.spec12(wire.VersionTLS12, suites, supported, allSchemes), "TLS 1.2 group order")
		f2 := p.hello(p.spec12(wire.VersionTLS12, suites, rev, allSchemes), "TLS 1.2 group order, reversed")
		res.Preference = groupPreference(f1.ske, f2.ske, supported[0], rev[0])
	}
	r.Groups12 = res
}

func groupPreference(a, b *wire.ServerKeyExchange, first, firstRev wire.Group) string {
	switch {
	case a == nil || b == nil:
		return "unknown"
	case a.Group == first && b.Group == firstRev:
		return "client"
	case a.Group == b.Group:
		return "server (prefers " + a.Group.Name() + ")"
	}
	return "mixed"
}

func (p *prober) probeGroups13(r *probeReport) {
	suites := r.suites13()
	res := &groupResult{}
	var supported []wire.Group
	for _, g := range probeGroups13 {
		f := p.hello(p.spec13(suites, []wire.Group{g}, allSchemes), "TLS 1.3 group "+g.Name())
		ir := itemResult{Group: g, Answer: f.answer(), Supported: f.sh != nil && f.sh.HelloRetryRequest && f.sh.KeyShare == g}
		if ir.Supported {
			supported = append(supported, g)
		}
		res.Results = append(res.Results, ir)
	}
	if len(supported) >= 2 {
		rev := slices.Clone(supported)
		slices.Reverse(rev)
		f1 := p.hello(p.spec13(suites, supported, allSchemes), "TLS 1.3 group order")
		f2 := p.hello(p.spec13(suites, rev, allSchemes), "TLS 1.3 group order, reversed")
		g1, g2 := hrrGroup(f1), hrrGroup(f2)
		switch {
		case g1 == 0 || g2 == 0:
			res.Preference = "unknown"
		case g1 == supported[0] && g2 == rev[0]:
			res.Preference = "client"
		case g1 == g2:
			res.Preference = "server (prefers " + g1.Name() + ")"
		default:
			res.Preference = "mixed"
		}
	}
	r.Groups13 = res
}

func hrrGroup(f *flight) wire.Group {
	if f.sh == nil || !f.sh.HelloRetryRequest {
		return 0
	}
	return f.sh.KeyShare
}

func (r *probeReport) supportedGroups12() []wire.Group {
	var out []wire.Group
	if r.Groups12 != nil {
		for _, x := range r.Groups12.Results {
			if x.Supported {
				out = append(out, x.Group)
			}
		}
	}
	if out == nil {
		return probeGroups12
	}
	return out
}

func (p *prober) probeSchemes12(r *probeReport) {
	suites := r.suites12(func(s wire.CipherSuite) bool { return s.IsECDHE() || s.IsDHE() })
	if len(suites) == 0 {
		r.Notes = append(r.Notes, "TLS 1.2 signature schemes not probed: no ECDHE or DHE cipher suite found")
		return
	}
	groups := r.supportedGroups12()
	for _, s := range probeSchemes12 {
		f := p.hello(p.spec12(wire.VersionTLS12, suites, groups, []wire.SignatureScheme{s}), "TLS 1.2 scheme "+s.Name())
		sr := schemeResult{Scheme: s, Answer: f.answer(), Supported: f.ske != nil && f.ske.SignatureScheme == s}
		if sr.Supported {
			sr.Certificate = certLabel(f.certs)
			p.seen(f.certs, "TLS 1.2 "+s.Name())
		}
		r.Schemes12 = append(r.Schemes12, sr)
	}
}

// probeSchemes13 runs full TLS 1.3 handshakes with crypto/tls, each
// offering one signature scheme: the server's signature is encrypted, so
// a raw ClientHello can't show it. A server that has no certificate for
// the scheme refuses the ClientHello; one that has sends its
// certificate.
func (p *prober) probeSchemes13(r *probeReport) {
	var groups []tls.CurveID
	if r.Groups13 != nil {
		for _, x := range r.Groups13.Results {
			if x.Supported && slices.Contains(goGroups13, x.Group) {
				groups = append(groups, tls.CurveID(x.Group))
			}
		}
	}
	if len(groups) == 0 {
		for _, g := range goGroups13 {
			groups = append(groups, tls.CurveID(g))
		}
	}
	for _, s := range probeSchemes13 {
		if p.n > 0 && p.delay > 0 {
			time.Sleep(p.delay)
		}
		p.n++
		var chain [][]byte
		var cri *tls.CertificateRequestInfo
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			ServerName: p.serverName, InsecureSkipVerify: true,
			CurvePreferences:           groups,
			KeyExchanges:               tlsutil.KeyExchanges(allBrainpool...),
			SignatureSchemes:           schemes13(s),
			VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				chain = raw
				return nil
			},
			GetClientCertificate: func(c *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cri = c
				for i := range p.ids {
					if c.SupportsCertificate(&p.ids[i]) == nil {
						return &p.ids[i], nil
					}
				}
				return &tls.Certificate{}, nil
			},
		}
		err := p.handshake13(cfg)
		sr := schemeResult{Scheme: s, Supported: chain != nil}
		switch {
		case err == nil:
			sr.Answer = "handshake completed"
		case chain != nil:
			sr.Answer = "certificate received; then: " + err.Error()
		default:
			sr.Answer = err.Error()
		}
		if sr.Supported {
			sr.Certificate = certLabel(chain)
			p.seen(chain, "TLS 1.3 "+s.Name())
		}
		if cri != nil {
			cr := &certRequestInfo{CAs: []string{}}
			for _, sc := range cri.SignatureSchemes {
				cr.SignatureSchemes = append(cr.SignatureSchemes, wire.SignatureScheme(sc))
			}
			for _, ca := range cri.AcceptableCAs {
				cr.CAs = append(cr.CAs, wire.DNString(ca))
			}
			p.noteCertRequest(wire.VersionTLS13, cr)
		}
		if p.trace != nil {
			fmt.Fprintf(p.trace, "probe %3d  %-44s -> %s\n", p.n, "TLS 1.3 scheme "+s.Name()+" (full handshake)", sr.Answer)
		}
		r.Schemes13 = append(r.Schemes13, sr)
	}
}

// certSchemes13 are signature schemes that TLS 1.3 allows only in
// certificates. crypto/tls takes signature_algorithms_cert from the same
// Config.SignatureSchemes but leaves these out of signature_algorithms.
var certSchemes13 = []tls.SignatureScheme{tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512, tls.PKCS1WithSHA1, tls.ECDSAWithSHA1}

// schemes13 returns the Config.SignatureSchemes that offer s alone for
// the handshake signature. Some servers (OpenSSL) also hold the
// signature of the certificate itself to signature_algorithms_cert, so
// offering s alone there too would refuse an RSA certificate signed with
// PKCS #1 v1.5 for an RSA-PSS scheme. An ECDSA certificate signed with
// another hash than s may still be refused by such servers.
func schemes13(s wire.SignatureScheme) []tls.SignatureScheme {
	return append([]tls.SignatureScheme{tls.SignatureScheme(s)}, certSchemes13...)
}

func (p *prober) handshake13(cfg *tls.Config) error {
	conn, err := p.dial.dial(context.Background(), p.addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.timeout))
	tc := tls.Client(conn, cfg)
	err = tc.Handshake()
	if err == nil {
		// The server may still reject our client certificate after its
		// Finished; read once to see its alert.
		conn.SetReadDeadline(time.Now().Add(p.timeout / 5))
		var b [1]byte
		if _, rerr := tc.Read(b[:]); rerr != nil && !isTimeout(rerr) && !errors.Is(rerr, io.EOF) {
			err = rerr
		}
	}
	tc.Close()
	return err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (p *prober) probeExtensions(r *probeReport) {
	suites := r.suites12(nil)
	if len(suites) == 0 {
		suites = wire.AllSuites()
	}
	groups := r.supportedGroups12()
	spec := p.spec12(wire.VersionTLS12, suites, groups, allSchemes)
	spec.SessionTicket, spec.StatusRequest, spec.SCT = true, true, true
	spec.ALPN = []string{"h2", "http/1.1"}
	f := p.hello(spec, "TLS 1.2 extensions")
	if f.sh == nil {
		// Some servers refuse ClientHellos with extensions they don't
		// know; fall back to the plain one.
		spec = p.spec12(wire.VersionTLS12, suites, groups, allSchemes)
		f = p.hello(spec, "TLS 1.2 without extra extensions")
	}
	res := &extensionResult{Answer: f.answer()}
	if f.sh != nil {
		res.ExtendedMasterSecret = f.sh.Has(wire.ExtExtendedMasterSecret)
		res.SecureRenegotiation = f.sh.Has(wire.ExtRenegotiationInfo)
		res.SessionTicket = f.sh.Has(wire.ExtSessionTicket)
		res.SessionID = len(f.sh.SessionID) > 0
		res.OCSPStapling = f.sh.Has(wire.ExtStatusRequest) && f.stapled
		res.SCT = f.sh.Has(wire.ExtSCT)
		res.ALPN = f.sh.ALPN
	}
	if cbc := r.suites12(wire.CipherSuite.IsCBC); len(cbc) > 0 {
		s := p.spec12(wire.VersionTLS12, cbc, groups, allSchemes)
		s.EncryptThenMAC = true
		f := p.hello(s, "TLS 1.2 encrypt_then_mac (CBC)")
		switch {
		case f.sh == nil:
			res.EncryptThenMAC = "unknown: " + f.answer()
		case f.sh.Has(wire.ExtEncryptThenMAC):
			res.EncryptThenMAC = "yes"
		default:
			res.EncryptThenMAC = "no"
		}
	}
	c := p.spec12(wire.VersionTLS12, suites, groups, allSchemes)
	c.Compression = []uint8{1, 0}
	cf := p.hello(c, "TLS 1.2 DEFLATE compression")
	switch {
	case cf.sh == nil:
		res.Compression = "unknown: " + cf.answer()
	case cf.sh.Compression == 0:
		res.Compression = "null only"
	default:
		res.Compression = fmt.Sprintf("method %d accepted", cf.sh.Compression)
	}
	r.Extensions = res
}

func (p *prober) probeFallback(r *probeReport) {
	var v wire.Version
	switch {
	case r.supports(wire.VersionTLS13) && r.supports(wire.VersionTLS12):
		v = wire.VersionTLS12
	case r.supports(wire.VersionTLS12) && r.supports(wire.VersionTLS11):
		v = wire.VersionTLS11
	case r.supports(wire.VersionTLS12) && r.supports(wire.VersionTLS10):
		v = wire.VersionTLS10
	default:
		r.Fallback = "not applicable (one protocol version)"
		return
	}
	spec := p.spec12(v, append(wire.AllSuites(), 0x5600), probeGroups12, allSchemes)
	f := p.hello(spec, "fallback to "+v.String()+" with SCSV")
	switch {
	case f.alert != nil && f.alert.Description == wire.AlertInappropriateFallback:
		r.Fallback = "enforced (inappropriate_fallback for " + v.String() + ")"
	case f.sh != nil:
		r.Fallback = "NOT enforced: " + f.answer()
		if f.sh.Downgrade != "" {
			r.Fallback += " (with the TLS 1.3 downgrade sentinel)"
		}
	default:
		r.Fallback = "unclear: " + f.answer()
	}
}

func (r *probeReport) printVersions(w io.Writer) {
	fmt.Fprintln(w, "Protocol versions")
	for _, v := range r.Versions {
		mark := "no "
		if v.Supported {
			mark = "yes"
		}
		kv(w, v.Version.String(), mark+"  "+v.Answer)
	}
}

func (r *probeReport) printSuites(w io.Writer) {
	for _, v := range []wire.Version{wire.VersionTLS13, wire.VersionTLS12, wire.VersionTLS11, wire.VersionTLS10} {
		res := r.Suites[v.String()]
		if res == nil {
			continue
		}
		fmt.Fprintf(w, "Cipher suites %v", v)
		if res.Preference != "" {
			fmt.Fprintf(w, " (%s preference)", res.Preference)
		}
		fmt.Fprintln(w)
		if len(res.Suites) == 0 {
			fmt.Fprintln(w, "  (none found)")
		}
		for _, s := range res.Suites {
			fmt.Fprintf(w, "  %v\n", s)
		}
	}
}

func (r *probeReport) printGroups(w io.Writer) {
	for _, x := range []struct {
		name string
		res  *groupResult
	}{{"TLS 1.2 (ServerKeyExchange)", r.Groups12}, {"TLS 1.3 (HelloRetryRequest)", r.Groups13}} {
		if x.res == nil {
			continue
		}
		fmt.Fprintf(w, "Groups %s", x.name)
		if x.res.Preference != "" {
			fmt.Fprintf(w, ", %s preference", x.res.Preference)
		}
		fmt.Fprintln(w)
		for _, g := range x.res.Results {
			mark := "no "
			if g.Supported {
				mark = "yes"
			}
			kv(w, g.Group.Name(), mark+"  "+g.Answer)
		}
	}
}

func (r *probeReport) printSchemes(w io.Writer) {
	for _, x := range []struct {
		name string
		res  []schemeResult
	}{{"TLS 1.2 (ServerKeyExchange)", r.Schemes12}, {"TLS 1.3 (full handshake)", r.Schemes13}} {
		if x.res == nil {
			continue
		}
		fmt.Fprintf(w, "Signature schemes %s\n", x.name)
		for _, s := range x.res {
			if s.Supported {
				fmt.Fprintf(w, "  %-34s yes  %s\n", s.Scheme.Name(), s.Certificate)
			} else {
				fmt.Fprintf(w, "  %-34s no   %s\n", s.Scheme.Name(), s.Answer)
			}
		}
	}
}

func (r *probeReport) printExtensions(w io.Writer) {
	e := r.Extensions
	if e == nil {
		return
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Fprintln(w, "Extensions and features (TLS 1.2)")
	kv(w, "ext. master secret", yes(e.ExtendedMasterSecret))
	kv(w, "secure renegotiation", yes(e.SecureRenegotiation))
	kv(w, "session tickets", yes(e.SessionTicket))
	kv(w, "session IDs", yes(e.SessionID))
	kv(w, "OCSP stapling", yes(e.OCSPStapling))
	kv(w, "SCT", yes(e.SCT))
	if e.ALPN != "" {
		kv(w, "ALPN", e.ALPN)
	} else {
		kv(w, "ALPN", "none selected (offered h2, http/1.1)")
	}
	if e.EncryptThenMAC != "" {
		kv(w, "encrypt-then-MAC", e.EncryptThenMAC)
	}
	kv(w, "compression", e.Compression)
}

func (r *probeReport) printCerts(w io.Writer) {
	if len(r.ClientAuth) > 0 {
		for _, ca := range r.ClientAuth {
			fmt.Fprintf(w, "Client certificate requested (%v)\n", ca.Version)
			ca.certRequestInfo.print(w)
		}
	}
	for i, c := range r.Certs {
		fmt.Fprintf(w, "Server certificate chain %d\n", i+1)
		kv(w, "seen with", strings.Join(c.SeenWith, "; "))
		c.chainReport.print(w)
	}
}

func (r *probeReport) printSummary(w io.Writer) {
	if len(r.TI) > 0 {
		fmt.Fprintln(w, "TI observations")
		for _, o := range r.TI {
			fmt.Fprintf(w, "  - %s\n", o)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	fmt.Fprintf(w, "%d probes in %.1f s\n", r.Probes, r.Duration)
}

// tiObservations compares the results with the TI settings of the ivory
// ti presets: the TLS 1.2 cipher suites (A_17124-03, GS-A_4384-03) and
// groups (GS-A_4384-03, A_17094-02). They are observations, not a
// conformance verdict: which requirements apply depends on the product
// type.
func (r *probeReport) tiObservations() []string {
	var out []string
	for _, v := range []wire.Version{wire.VersionSSL30, wire.VersionTLS10, wire.VersionTLS11} {
		if r.supports(v) {
			out = append(out, v.String()+" is supported (the TI uses TLS 1.2 and 1.3)")
		}
	}
	if res := r.Suites[wire.VersionTLS12.String()]; res != nil && len(res.Suites) > 0 {
		var have, missing, other []string
		tiSuites := slices.Concat(ti.SuitesECDSA, ti.SuitesRSA)
		for _, s := range tiSuites {
			if slices.Contains(res.Suites, wire.CipherSuite(s)) {
				have = append(have, wire.CipherSuite(s).Name())
			} else {
				missing = append(missing, wire.CipherSuite(s).Name())
			}
		}
		for _, s := range res.Suites {
			if !slices.Contains(tiSuites, uint16(s)) {
				other = append(other, s.Name())
			}
		}
		out = append(out, fmt.Sprintf("TI TLS 1.2 cipher suites supported: %d of %d", len(have), len(tiSuites)))
		if len(missing) > 0 {
			out = append(out, "TI TLS 1.2 cipher suites not supported: "+strings.Join(missing, ", "))
		}
		if len(other) > 0 {
			out = append(out, "other TLS 1.2 cipher suites supported: "+strings.Join(other, ", "))
		}
	}
	if r.Groups12 != nil {
		var have, missing []string
		for _, c := range append(slices.Clone(ti.Curves), tlsutil.CurveBrainpoolP512r1) {
			for _, x := range r.Groups12.Results {
				if x.Group == wire.Group(c) {
					if x.Supported {
						have = append(have, x.Group.Name())
					} else {
						missing = append(missing, x.Group.Name())
					}
				}
			}
		}
		out = append(out, "TI groups in TLS 1.2: supported "+strings.Join(have, ", ")+"; not supported "+orNone(missing))
	}
	if r.supports(wire.VersionTLS13) && r.Groups13 != nil {
		var bp []string
		for _, x := range r.Groups13.Results {
			if x.Supported && x.Group >= 0x001f && x.Group <= 0x0021 {
				bp = append(bp, x.Group.Name())
			}
		}
		out = append(out, "TLS 1.3 Brainpool groups (RFC 8734): "+orNone(bp))
	}
	if r.Schemes13 != nil {
		var bp []string
		for _, s := range r.Schemes13 {
			if s.Supported && s.Scheme >= 0x081a && s.Scheme <= 0x081c {
				bp = append(bp, s.Scheme.Name())
			}
		}
		out = append(out, "TLS 1.3 Brainpool signature schemes (RFC 8734): "+orNone(bp))
	}
	var keys []string
	for _, c := range r.Certs {
		if len(c.Certificates) > 0 && !slices.Contains(keys, c.Certificates[0].Key) {
			keys = append(keys, c.Certificates[0].Key)
		}
	}
	if len(keys) > 0 {
		out = append(out, "server identities: "+strings.Join(keys, ", "))
	}
	if e := r.Extensions; e != nil {
		if !e.ExtendedMasterSecret {
			out = append(out, "no extended master secret (RFC 7627) in TLS 1.2")
		}
		if !e.SecureRenegotiation {
			out = append(out, "no renegotiation_info (RFC 5746) in TLS 1.2")
		}
	}
	return out
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
