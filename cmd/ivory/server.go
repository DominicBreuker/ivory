//go:build ivory

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	"github.com/DominicBreuker/ivory/tlsutil"
)

const serverUsage = `usage: ivory server [flags]

Accepts TLS connections and reports, for each, what the client offered
(versions, cipher suites, groups, signature schemes, extensions, JA3),
what was negotiated, and the client certificate read the TI way, with the
TI check if -env, -tsl or -ca is given. Without -cert and -key it serves
fresh self-signed identities (brainpoolP256r1, P-256, RSA 2048).

`

type serverReport struct {
	Remote             string        `json:"remote"`
	Time               time.Time     `json:"time"`
	ClientHello        *helloProfile `json:"client_hello,omitempty"`
	Handshake          handshakeInfo `json:"handshake"`
	Identity           string        `json:"server_identity,omitempty"`
	ClientCertificates *chainReport  `json:"client_certificate_chain,omitempty"`
	Data               *dataResult   `json:"data,omitempty"`
	Trace              []traceEvent  `json:"trace,omitempty"`
}

// helloProfile is a decoded ClientHello with its JA3 fingerprint.
type helloProfile struct {
	*wire.ClientHello
	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`
}

type dataResult struct {
	Bytes   int    `json:"bytes"`
	First   string `json:"first_line,omitempty"`
	Replied string `json:"replied,omitempty"`
}

type serverOptions struct {
	clientAuth          tls.ClientAuthType
	idle                time.Duration
	jsonOut, trace, hex bool
	httpReply           bool
	ts                  *trustSpace
	identityNames       map[[32]byte]string
}

func runServer(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		tf                 tlsFlags
		trust              trustFlags
		dial               dialer
		ids                identityFlags
		addr, auth, keyLog string
		names              string
		idle               time.Duration
		once               bool
		o                  serverOptions
	)
	tf.register(fs)
	trust.register(fs, false)
	dial.registerDownloads(fs)
	ids.register(fs, "server")
	fs.StringVar(&addr, "addr", ":4433", "listen `address`")
	fs.StringVar(&auth, "client-auth", "request", "client certificate: none, request (ask, accept none) or require")
	fs.StringVar(&names, "name", "localhost,127.0.0.1", "comma-separated DNS names and IP addresses of the generated identities")
	fs.StringVar(&keyLog, "keylog", "", "append TLS secrets to this `file` (NSS key log format, for Wireshark)")
	fs.DurationVar(&idle, "idle", 10*time.Second, "close a connection after this long without data")
	fs.BoolVar(&once, "once", false, "exit after the first connection")
	fs.BoolVar(&o.httpReply, "http", false, "answer an HTTP request with a plain-text summary of the connection")
	fs.BoolVar(&o.jsonOut, "json", false, "print one JSON object per connection")
	fs.BoolVar(&o.trace, "trace", false, "print every TLS record and decoded handshake message")
	fs.BoolVar(&o.hex, "hex", false, "with -trace, add a hex dump of every record")
	fs.Usage = func() {
		fmt.Fprint(stderr, serverUsage)
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\n"+profileHelp)
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		fs.Usage()
		return errUsage
	}
	switch auth {
	case "none":
		o.clientAuth = tls.NoClientCert
	case "request":
		o.clientAuth = tls.RequestClientCert
	case "require":
		// Any certificate: the report checks it, the handshake doesn't.
		o.clientAuth = tls.RequireAnyClientCert
	default:
		return fmt.Errorf("-client-auth: want none, request or require, not %q", auth)
	}
	o.idle = idle
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "ivory: "+format+"\n", a...) }
	trust.client = dial.httpClient()
	if o.ts, err = trust.load(context.Background(), logf); err != nil {
		return err
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
	o.identityNames = map[[32]byte]string{}
	for _, c := range certs {
		info := describeDER(c.Certificate[0])
		o.identityNames[sha256.Sum256(c.Certificate[0])] = info.Subject + " (" + info.Key + ")"
		logf("identity %s, %s, sha256 %s", info.Subject, info.Key, info.SHA256)
	}
	cfg, err := tf.config()
	if err != nil {
		return err
	}
	cfg.GetCertificate = tlsutil.GetCertificate(certs)
	cfg.ClientAuth = o.clientAuth
	cfg.SessionTicketsDisabled = true
	if cfg.MinVersion <= tls.VersionTLS12 && cfg.MaxVersion >= tls.VersionTLS13 {
		cfg.GetConfigForClient = tlsutil.TLS12Fallback(cfg, certs)
	}
	if keyLog != "" {
		f, err := os.OpenFile(keyLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		cfg.KeyLogWriter = f
	}
	ln, err := listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	logf("listening on %s, profile %s, client certificates: %s", ln.Addr(), tf.profile, auth)
	return serve(ln, cfg, &o, once, stdout)
}

// listen is net.Listen; tests replace it to learn the address.
var listen = net.Listen

func serve(ln net.Listener, cfg *tls.Config, o *serverOptions, once bool, stdout io.Writer) error {
	var out sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		wg.Add(1)
		handle := func() {
			defer wg.Done()
			r, text := handleConn(c, cfg, o)
			out.Lock()
			defer out.Unlock()
			if o.jsonOut {
				writeJSON(stdout, r, false)
			} else {
				io.WriteString(stdout, text)
			}
		}
		if once {
			handle()
			return nil
		}
		go handle()
	}
}

// handleConn runs one connection and returns its report, and the text
// form of it including the live trace.
func handleConn(c net.Conn, cfg *tls.Config, o *serverOptions) (*serverReport, string) {
	defer c.Close()
	var buf strings.Builder
	var live io.Writer
	if o.trace && !o.jsonOut {
		live = &buf
		fmt.Fprintf(&buf, "Trace of %s\n", c.RemoteAddr())
	}
	hl := newHandshakeLog(live, o.hex, o.trace && o.jsonOut)
	r := &serverReport{Remote: c.RemoteAddr().String(), Time: time.Now().UTC()}
	c.SetDeadline(time.Now().Add(o.idle))
	conn := tls.Server(&tracedConn{Conn: c, log: hl}, cfg)
	start := time.Now()
	err := conn.Handshake()
	r.Handshake.Duration = time.Since(start).Seconds()
	var state *tls.ConnectionState
	if err == nil {
		r.Handshake.OK = true
		s := conn.ConnectionState()
		state = &s
		if len(s.LocalCertificate) > 0 {
			r.Identity = o.identityNames[sha256.Sum256(s.LocalCertificate[0])]
		}
	} else {
		r.Handshake.Error = err.Error()
	}
	r.Handshake.fill(state, hl, dirS2C)
	hl.mu.Lock()
	if hl.clientHello != nil {
		ja3, sum := wire.JA3(hl.clientHello)
		r.ClientHello = &helloProfile{ClientHello: hl.clientHello, JA3: ja3, JA3Hash: sum}
	}
	clientCerts := hl.clientCerts
	hl.mu.Unlock()
	if state != nil && len(state.PeerCertificates) > 0 {
		clientCerts = nil
		for _, pc := range state.PeerCertificates {
			clientCerts = append(clientCerts, pc.Raw)
		}
	}
	r.ClientCertificates = newChainReport(context.Background(), clientCerts, o.ts)
	if err == nil {
		r.Data = readData(conn, o, r)
	}
	if o.trace && o.jsonOut {
		r.Trace = hl.trace()
	}
	r.print(&buf)
	return r, buf.String()
}

// readData reads what the client sends until it closes the connection
// or is idle; with -http it answers the first request.
func readData(conn *tls.Conn, o *serverOptions, r *serverReport) *dataResult {
	d := &dataResult{}
	conn.SetDeadline(time.Now().Add(o.idle))
	br := bufio.NewReader(conn)
	if o.httpReply {
		req, err := http.ReadRequest(br)
		if err == nil {
			d.First = req.Method + " " + req.RequestURI + " " + req.Proto
			var body strings.Builder
			r.print(&body)
			resp := &http.Response{
				StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1, Close: true,
				Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
				ContentLength: int64(body.Len()),
				Body:          io.NopCloser(strings.NewReader(body.String())),
			}
			if resp.Write(conn) == nil {
				d.Replied = "200 OK"
			}
			return d
		}
	}
	for {
		conn.SetReadDeadline(time.Now().Add(o.idle))
		line, err := br.ReadString('\n')
		if d.First == "" && line != "" {
			d.First = strings.TrimRight(line, "\r\n")
			if len(d.First) > 200 {
				d.First = d.First[:200]
			}
		}
		d.Bytes += len(line)
		if err != nil {
			break
		}
	}
	return d
}

func (r *serverReport) print(w io.Writer) {
	fmt.Fprintf(w, "Connection from %s at %s\n", r.Remote, r.Time.Format(time.RFC3339))
	if ch := r.ClientHello; ch != nil {
		fmt.Fprintln(w, "ClientHello")
		kv(w, "legacy_version", ch.Version.String())
		if ch.SupportedVersions != nil {
			kv(w, "versions", joinStrings(ch.SupportedVersions))
		}
		kv(w, "cipher suites", joinNames(ch.CipherSuites))
		kv(w, "groups", joinNames(ch.SupportedGroups))
		if ch.KeyShares != nil {
			kv(w, "key shares", joinNames(ch.KeyShares))
		}
		kv(w, "signature algs", joinNames(ch.SignatureAlgorithms))
		if ch.SignatureAlgorithmsCert != nil {
			kv(w, "sig. algs (cert)", joinNames(ch.SignatureAlgorithmsCert))
		}
		var exts []wire.ExtensionType
		for _, e := range ch.Extensions {
			exts = append(exts, e.Type)
		}
		kv(w, "extensions", joinNames(exts))
		if ch.ServerName != "" {
			kv(w, "server name", ch.ServerName)
		}
		if ch.ALPN != nil {
			kv(w, "ALPN", strings.Join(ch.ALPN, ", "))
		}
		if len(ch.Compression) != 1 || ch.Compression[0] != 0 {
			kv(w, "compression", fmt.Sprint(ch.Compression))
		}
		kv(w, "JA3", ch.JA3Hash+" "+ch.JA3)
	}
	fmt.Fprintln(w, "Result")
	r.Handshake.print(w)
	if r.Identity != "" {
		kv(w, "our identity", r.Identity)
	}
	if r.ClientCertificates != nil {
		fmt.Fprintln(w, "Client certificate chain")
		r.ClientCertificates.print(w)
	} else if r.Handshake.OK {
		kv(w, "client cert", "none")
	}
	if d := r.Data; d != nil {
		kv(w, "data", fmt.Sprintf("%d bytes", d.Bytes))
		if d.First != "" {
			kv(w, "first line", fmt.Sprintf("%q", d.First))
		}
		if d.Replied != "" {
			kv(w, "replied", d.Replied)
		}
	}
	fmt.Fprintln(w)
}

func joinStrings[T fmt.Stringer](v []T) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = x.String()
	}
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ", ")
}
