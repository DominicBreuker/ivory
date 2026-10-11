//go:build ivory

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DominicBreuker/ivory/cmd/ivory/internal/wire"
)

const clientUsage = `usage: ivory client [flags] host[:port]

Connects once, prints what the handshake negotiated, the server's
certificate chain read the TI way (certificate type, roles, key) and,
with -env, -tsl or -ca, the TI check of the server certificate.

`

type clientReport struct {
	Address            string           `json:"address"`
	ServerName         string           `json:"server_name,omitempty"`
	Proxy              string           `json:"proxy,omitempty"`
	Profile            string           `json:"profile"`
	Handshake          handshakeInfo    `json:"handshake"`
	Server             *chainReport     `json:"server_certificate_chain,omitempty"`
	WebPKI             string           `json:"web_pki_check,omitempty"`
	CertificateRequest *certRequestInfo `json:"certificate_request,omitempty"`
	ClientCertificate  *CertInfo        `json:"client_certificate_sent,omitempty"`
	HTTP               *httpResult      `json:"http,omitempty"`
	Trace              []traceEvent     `json:"trace,omitempty"`
}

type httpResult struct {
	Status  string      `json:"status,omitempty"`
	Header  http.Header `json:"header,omitempty"`
	BodyLen int         `json:"body_length"`
	Error   string      `json:"error,omitempty"`
}

func runClient(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		tf                  tlsFlags
		trust               trustFlags
		ids                 identityFlags
		dial                dialer
		serverName, keyLog  string
		httpPath            string
		timeout             time.Duration
		jsonOut, trace, hex bool
	)
	tf.register(fs)
	trust.register(fs, true)
	ids.register(fs, "client")
	dial.register(fs)
	fs.StringVar(&serverName, "servername", "", "server name for SNI (default: the host, unless it is an IP address)")
	fs.StringVar(&keyLog, "keylog", "", "append TLS secrets to this `file` (NSS key log format, for Wireshark)")
	fs.StringVar(&httpPath, "http", "", "after the handshake, send an HTTP GET for this `path` and report the response")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "connection and handshake timeout")
	fs.BoolVar(&jsonOut, "json", false, "print the report as JSON")
	fs.BoolVar(&trace, "trace", false, "print every TLS record and decoded handshake message")
	fs.BoolVar(&hex, "hex", false, "with -trace, add a hex dump of every record")
	fs.Usage = func() {
		fmt.Fprint(stderr, clientUsage)
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\n"+profileHelp)
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return errUsage
	}
	addr := withPort(pos[0], "443")
	if err := trust.guard(); err != nil {
		return err
	}
	ctx := context.Background()
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "ivory: "+format+"\n", a...) }
	trust.client = dial.httpClient()
	ts, err := trust.load(ctx, logf)
	if err != nil {
		return err
	}
	identities, err := ids.load()
	if err != nil {
		return err
	}
	cfg, err := tf.config()
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}
	cfg.ServerName = serverName
	// The report checks the server certificate the TI way; crypto/x509
	// can't verify Brainpool chains.
	cfg.InsecureSkipVerify = true
	if keyLog != "" {
		f, err := os.OpenFile(keyLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		cfg.KeyLogWriter = f
	}

	var live io.Writer
	if trace && !jsonOut {
		live = stdout
	}
	hl := newHandshakeLog(live, hex, trace && jsonOut)
	dial.timeout = timeout
	report := &clientReport{Address: addr, ServerName: serverName, Proxy: dial.describe(addr), Profile: tf.profile}
	var (
		mu        sync.Mutex
		peerCerts [][]byte
	)
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		mu.Lock()
		peerCerts = raw
		mu.Unlock()
		return nil
	}
	cfg.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cr := &certRequestInfo{CAs: []string{}}
		for _, s := range cri.SignatureSchemes {
			cr.SignatureSchemes = append(cr.SignatureSchemes, wire.SignatureScheme(s))
		}
		for _, ca := range cri.AcceptableCAs {
			cr.CAs = append(cr.CAs, wire.DNString(ca))
		}
		hl.note("server requests a client certificate: %d acceptable CAs, schemes %s", len(cr.CAs), joinNames(cr.SignatureSchemes))
		mu.Lock()
		report.CertificateRequest = cr
		mu.Unlock()
		for i := range identities {
			if cri.SupportsCertificate(&identities[i]) == nil {
				hl.note("sending client identity %d", i+1)
				return &identities[i], nil
			}
		}
		if len(identities) > 0 {
			hl.note("no client identity fits the request; sending the first anyway")
			return &identities[0], nil
		}
		hl.note("no client identity (-cert, -key): sending none")
		return &tls.Certificate{}, nil
	}

	start := time.Now()
	raw, err := dial.dial(ctx, addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(timeout))
	conn := tls.Client(&tracedConn{Conn: raw, log: hl, client: true}, cfg)
	err = conn.HandshakeContext(ctx)
	report.Handshake.Duration = time.Since(start).Seconds()
	var state *tls.ConnectionState
	if err == nil {
		report.Handshake.OK = true
		s := conn.ConnectionState()
		state = &s
		if len(s.LocalCertificate) > 0 {
			ci := describeDER(s.LocalCertificate[0])
			report.ClientCertificate = &ci
		}
	} else {
		report.Handshake.Error = err.Error()
	}
	report.Handshake.fill(state, hl, dirC2S)
	hl.mu.Lock()
	if report.CertificateRequest != nil && hl.certReq != nil {
		for _, t := range hl.certReq.CertificateTypes {
			report.CertificateRequest.CertificateTypes = append(report.CertificateRequest.CertificateTypes, wire.CertificateTypeName(t))
		}
	} else if report.CertificateRequest == nil && hl.certReq != nil {
		report.CertificateRequest = certRequestFromWire(hl.certReq)
	}
	if peerCerts == nil {
		peerCerts = hl.serverCerts
	}
	hl.mu.Unlock()
	if err == nil && httpPath != "" {
		report.HTTP = httpGet(conn, serverName, host, httpPath)
	}
	conn.Close()
	report.Server = newChainReport(ctx, peerCerts, ts)
	report.WebPKI = webPKICheck(peerCerts, serverName)
	if trace && jsonOut {
		report.Trace = hl.trace()
	}

	if jsonOut {
		if err := writeJSON(stdout, report, true); err != nil {
			return err
		}
	} else {
		report.print(stdout)
	}
	switch {
	case !report.Handshake.OK:
		return errFailed
	case report.Server != nil && report.Server.TICheck != nil && report.Server.TICheck.Result != "ok":
		return errCheckFailed
	}
	return nil
}

// webPKICheck verifies the chain against the system's roots for the
// server name, as a browser would: TI services reachable from the
// internet present certificates of public CAs, not of the TI's PKI.
func webPKICheck(chain [][]byte, serverName string) string {
	if len(chain) == 0 || serverName == "" {
		return ""
	}
	var certs []*x509.Certificate
	for _, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "FAILED: " + err.Error()
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: serverName, Intermediates: inter}); err != nil {
		return "FAILED: " + err.Error()
	}
	return "ok"
}

func certRequestFromWire(cr *wire.CertificateRequest) *certRequestInfo {
	out := &certRequestInfo{CAs: cr.CANames, SignatureSchemes: cr.SignatureAlgorithms}
	for _, t := range cr.CertificateTypes {
		out.CertificateTypes = append(out.CertificateTypes, wire.CertificateTypeName(t))
	}
	return out
}

func (r *clientReport) print(w io.Writer) {
	fmt.Fprintf(w, "Connection to %s", r.Address)
	if r.ServerName != "" {
		fmt.Fprintf(w, " (SNI %s)", r.ServerName)
	}
	if r.Proxy != "" {
		fmt.Fprintf(w, " via proxy %s", r.Proxy)
	}
	fmt.Fprintf(w, ", profile %s\n", r.Profile)
	r.Handshake.print(w)
	if r.Server != nil {
		fmt.Fprintln(w, "Server certificate chain")
		r.Server.print(w)
	}
	if r.WebPKI != "" {
		fmt.Fprintln(w, "Web PKI check")
		kv(w, "result", r.WebPKI)
	}
	if r.CertificateRequest != nil {
		fmt.Fprintln(w, "Client certificate requested")
		r.CertificateRequest.print(w)
		if r.ClientCertificate != nil {
			kv(w, "sent", r.ClientCertificate.Subject+" ("+r.ClientCertificate.Key+")")
		} else {
			kv(w, "sent", "none")
		}
	}
	if h := r.HTTP; h != nil {
		fmt.Fprintln(w, "HTTP")
		if h.Error != "" {
			kv(w, "error", h.Error)
		} else {
			kv(w, "status", h.Status)
			for k, v := range h.Header {
				kv(w, k, strings.Join(v, ", "))
			}
			kv(w, "body", fmt.Sprintf("%d bytes", h.BodyLen))
		}
	}
}

func httpGet(conn *tls.Conn, serverName, host, path string) *httpResult {
	if serverName != "" {
		host = serverName
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return &httpResult{Error: err.Error()}
	}
	req.Close = true
	req.Header.Set("User-Agent", "ivory")
	if err := req.Write(conn); err != nil {
		return &httpResult{Error: err.Error()}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return &httpResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return &httpResult{Status: resp.Status, Header: resp.Header, BodyLen: int(n)}
}

// withPort adds port to addr if it has none.
func withPort(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), port)
}
