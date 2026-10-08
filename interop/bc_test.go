//go:build ivory

package interop

// Interop with BouncyCastle's TLS provider for Java (BCJSSE), which many
// TI products use (README.md): B1-B5. The BouncyCastle peer is
// testdata/bcpeer/BCPeer.java. The tests need a JDK (java and javac, 11 or
// later) and the BouncyCastle jars in the directory $IVORY_BCJARS
// (scripts/fetch-bouncycastle.sh). They are skipped without them, unless
// $IVORY_REQUIRE_BC is set (the CI job bc).

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/tlsutil"
)

var bcBuild struct {
	once sync.Once
	dir  string // the compiled BCPeer
	cp   string // class path: dir and the jars
	err  error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if bcBuild.dir != "" {
		os.RemoveAll(bcBuild.dir)
	}
	os.Exit(code)
}

// needBC compiles BCPeer once and returns the java binary and the class
// path for it. It skips the test if a JDK or the jars are missing, or fails
// it if $IVORY_REQUIRE_BC is set.
func needBC(t *testing.T) (java, cp string) {
	t.Helper()
	skip := t.Skipf
	if os.Getenv("IVORY_REQUIRE_BC") != "" {
		skip = t.Fatalf
	}
	jars := os.Getenv("IVORY_BCJARS")
	if jars == "" {
		skip("IVORY_BCJARS is not set (scripts/fetch-bouncycastle.sh)")
		return
	}
	java, err := exec.LookPath("java")
	if err != nil {
		skip("java not found")
		return
	}
	javac, err := exec.LookPath("javac")
	if err != nil {
		skip("javac not found")
		return
	}
	bcBuild.once.Do(func() {
		dir, err := os.MkdirTemp("", "ivory-bcpeer")
		if err != nil {
			bcBuild.err = err
			return
		}
		bcBuild.dir = dir
		cp := dir + string(filepath.ListSeparator) + filepath.Join(jars, "*")
		out, err := exec.Command(javac, "-d", dir, "-cp", cp, filepath.Join("testdata", "bcpeer", "BCPeer.java")).CombinedOutput()
		if err != nil {
			bcBuild.err = errors.New("javac: " + err.Error() + "\n" + string(out))
			return
		}
		bcBuild.cp = cp
	})
	if bcBuild.err != nil {
		skip("%v", bcBuild.err)
		return
	}
	return java, bcBuild.cp
}

// startBC starts a BCPeer in mode "server" or "client" with flags.
func startBC(t *testing.T, mode string, flags ...string) *peerProc {
	t.Helper()
	java, cp := needBC(t)
	return startPeer(t, java, append([]string{"-cp", cp, "BCPeer", mode}, flags...)...)
}

// bcFlags are the identity, trust and protocol flags of a BCPeer.
func bcFlags(identity, ca, protocol, groups string) []string {
	f := []string{"-ca", pkiFile(ca + ".pem"), "-protocol", protocol, "-groups", groups}
	if identity != "" {
		f = append(f, "-cert", pkiFile(identity+".pem"), "-key", pkiFile(identity+".key"))
	}
	return f
}

// clientWithBCServer runs a Go client against a BCPeer server. On success
// it waits until the BCPeer received the greeting.
func clientWithBCServer(t *testing.T, config *tls.Config, flags ...string) (tls.ConnectionState, string, error) {
	t.Helper()
	addr := freeAddr(t)
	p := startBC(t, "server", append([]string{"-addr", addr}, flags...)...)
	if !p.waitFor("listening ") {
		t.Fatalf("BCPeer didn't start:\n%s", p.output())
	}
	cs, err := goClient(addr, config)
	if err == nil && !p.waitFor("received "+greeting) {
		err = errors.New("BCPeer didn't receive the greeting")
	}
	return cs, p.stop(), err
}

// serverWithBCClient runs a Go server with config against a BCPeer client.
// On success the server sends the greeting and the function waits until
// the BCPeer received it.
func serverWithBCClient(t *testing.T, config *tls.Config, flags ...string) (tls.ConnectionState, string, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		cs   tls.ConnectionState
		err  error
		conn net.Conn
	}
	results := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			results <- result{err: err}
			return
		}
		conn.SetDeadline(time.Now().Add(opTimeout))
		c := tls.Server(conn, config)
		if err := c.Handshake(); err != nil {
			results <- result{err: err, conn: conn}
			return
		}
		_, err = io.WriteString(c, greeting+"\n")
		results <- result{cs: c.ConnectionState(), err: err, conn: conn}
	}()
	p := startBC(t, "client", append([]string{"-addr", ln.Addr().String()}, flags...)...)
	var r result
	select {
	case r = <-results:
	case <-time.After(opTimeout):
		t.Fatalf("timeout waiting for the Go server; BCPeer:\n%s", p.output())
	}
	if r.conn != nil {
		defer r.conn.Close()
	}
	if r.err == nil && !p.waitFor("received "+greeting) {
		r.err = errors.New("BCPeer didn't receive the greeting")
	}
	return r.cs, p.stop(), r.err
}

func wantBC(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(out, l) {
			t.Errorf("BCPeer output lacks %q", l)
		}
	}
}

var bcCurves = []struct {
	bits  string
	curve brainpool.Curve
	group tls.CurveID // TLS 1.2
	name  string      // BCJSSE's name of the TLS 1.2 group
}{
	{"256", brainpool.P256r1(), tlsutil.CurveBrainpoolP256r1, "brainpoolP256r1"},
	{"384", brainpool.P384r1(), tlsutil.CurveBrainpoolP384r1, "brainpoolP384r1"},
	{"512", brainpool.P512r1(), tlsutil.CurveBrainpoolP512r1, "brainpoolP512r1"},
}

// B1: Go server with a Brainpool certificate, requiring a client
// certificate; BouncyCastle client with a Brainpool certificate, TLS 1.2.
// The client offers only the Brainpool group of its curve, or P-256 first.
func TestB1GoServerBCClient(t *testing.T) {
	for _, tt := range bcCurves {
		bp := "bp" + tt.bits
		for _, g := range []struct {
			groups string
			want   tls.CurveID
		}{
			{tt.name, tt.group},
			{"secp256r1," + tt.name, tls.CurveP256},
		} {
			t.Run(bp+" "+g.groups, func(t *testing.T) {
				config := brainpoolServer(t, bp+"-server", bp+"-ca")
				config.KeyExchanges = tlsutil.KeyExchanges(tt.curve)
				cs, out, err := serverWithBCClient(t, config,
					append(bcFlags(bp+"-client", bp+"-ca", "TLSv1.2", g.groups), "-servername", "localhost")...)
				if err != nil {
					t.Fatal(err)
				}
				checkPeer(t, cs, "ivory Brainpool P"+tt.bits+" Client", g.want)
				wantBC(t, out, "protocol TLSv1.2", "suite TLS_ECDHE_ECDSA_", "peer CN=localhost")
			})
		}
	}
}

// B2: Go client with a Brainpool client certificate; BouncyCastle server
// with a Brainpool certificate that requires a client certificate, TLS
// 1.2, Brainpool groups only.
func TestB2GoClientBCServer(t *testing.T) {
	for _, tt := range bcCurves {
		bp := "bp" + tt.bits
		t.Run(bp, func(t *testing.T) {
			config := brainpoolClient(t, bp+"-client", bp+"-ca")
			config.KeyExchanges = tlsutil.KeyExchanges(tt.curve)
			config.CurvePreferences = []tls.CurveID{tls.CurveP256, tt.group}
			cs, out, err := clientWithBCServer(t, config,
				append(bcFlags(bp+"-server", bp+"-ca", "TLSv1.2", tt.name), "-clientauth")...)
			if err != nil {
				t.Fatal(err)
			}
			checkPeer(t, cs, "localhost", tt.group)
			wantBC(t, out, "protocol TLSv1.2", "suite TLS_ECDHE_ECDSA_", "peer CN=ivory Brainpool P"+tt.bits+" Client")
		})
	}
}

// B3: TLS 1.3 with Brainpool certificates and groups (RFC 8734) in both
// roles, mutual authentication, on all three curves.
func TestB3TLS13(t *testing.T) {
	for _, tt := range tls13Curves {
		bp := "bp" + tt.bits
		t.Run("Go server "+bp, func(t *testing.T) {
			var r schemeRecorder
			config := tls13Config(brainpoolServer(t, bp+"-server", bp+"-ca"), &r, tt.curve)
			cs, out, err := serverWithBCClient(t, config,
				append(bcFlags(bp+"-client", bp+"-ca", "TLSv1.3", tt.name), "-servername", "localhost")...)
			if err != nil {
				t.Fatal(err)
			}
			checkTLS13(t, cs, "ivory Brainpool P"+tt.bits+" Client", tt.group, false)
			checkSchemes(t, "server", r.get(), tt.scheme)
			wantBC(t, out, "protocol TLSv1.3", "peer CN=localhost")
		})
		t.Run("Go client "+bp, func(t *testing.T) {
			var r schemeRecorder
			config := tls13Config(brainpoolClient(t, bp+"-client", bp+"-ca"), &r, tt.curve)
			config.CurvePreferences = []tls.CurveID{tt.group}
			cs, out, err := clientWithBCServer(t, config,
				append(bcFlags(bp+"-server", bp+"-ca", "TLSv1.3", tt.name), "-clientauth")...)
			if err != nil {
				t.Fatal(err)
			}
			checkTLS13(t, cs, "localhost", tt.group, false)
			checkSchemes(t, "client", r.get(), tt.scheme)
			wantBC(t, out, "protocol TLSv1.3", "peer CN=ivory Brainpool P"+tt.bits+" Client")
		})
	}
}

// B4: an eHealth-KT (ti.KTServer) with an RSA and a Brainpool identity
// against a BouncyCastle client with a Brainpool client certificate, like
// a Konnektor: the Brainpool identity on ECDSA suites, the RSA identity on
// RSA suites (A_22453). With the profile kt, the KT asks only for RSA
// client certificates on RSA suites (A_22454), so the client sends none
// and the handshake goes on without one (A_22890).
func TestB4KTServerBCClient(t *testing.T) {
	for _, tt := range []struct {
		name, suites, ca string
		wantSuite        uint16
		wantClientCert   bool
	}{
		{"ECDSA suites", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "bp256-ca", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true},
		{"RSA suites", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "rsa-ca", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, !ktProfile},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flags := []string{"-cert", pkiFile("bp256-client.pem"), "-key", pkiFile("bp256-client.key"),
				"-ca", pkiFile(tt.ca + ".pem"), "-protocol", "TLSv1.2",
				"-groups", "secp256r1,secp384r1,brainpoolP256r1,brainpoolP384r1", "-suites", tt.suites}
			cs, out, err := serverWithBCClient(t, ktConfig(t), flags...)
			if err != nil {
				t.Fatal(err)
			}
			if cs.CipherSuite != tt.wantSuite {
				t.Errorf("cipher suite = %s, want %s", tls.CipherSuiteName(cs.CipherSuite), tls.CipherSuiteName(tt.wantSuite))
			}
			if got := len(cs.PeerCertificates) > 0; got != tt.wantClientCert {
				t.Errorf("client certificate sent = %v, want %v", got, tt.wantClientCert)
			} else if got && cs.PeerCertificates[0].Subject.CommonName != "ivory Brainpool P256 Client" {
				t.Errorf("client certificate %q, want the Brainpool one", cs.PeerCertificates[0].Subject.CommonName)
			}
			wantBC(t, out, "protocol TLSv1.2", "suite "+tls.CipherSuiteName(tt.wantSuite))
		})
	}
}

// B5: a Konnektor-like Go client (ti.ConnectorClientConfig) against a
// BouncyCastle server with a Brainpool identity that requires a client
// certificate, like a card terminal.
func TestB5ConnectorClientBCServer(t *testing.T) {
	config := connectorConfig(t)
	cs, out, err := clientWithBCServer(t, config,
		append(bcFlags("bp256-server", "bp256-ca", "TLSv1.2", "brainpoolP256r1,secp256r1"), "-clientauth")...)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Version != tls.VersionTLS12 || len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != "localhost" {
		t.Errorf("version %x, peer certificates %v", cs.Version, cs.PeerCertificates)
	}
	wantBC(t, out, "protocol TLSv1.2", "suite TLS_ECDHE_ECDSA_", "peer CN=ivory Brainpool P256 Client")
}
