//go:build ivory

package interop

// TLS 1.3 interop (README.md): I13 Go <-> Go on all three curves with
// groups 31-33, I14 HelloRetryRequest, I15 and I16 against OpenSSL >= 3.2,
// which has Brainpool groups and signature schemes in TLS 1.3 (RFC 8734).

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/tlsutil"
)

// useOpenSSL3 makes the test use OpenSSL 3.2 or later: $IVORY_OPENSSL3, or
// openssl on PATH. It skips the test if there is none, or fails it if
// $IVORY_REQUIRE_TLS13 is set (the CI job tls13).
func useOpenSSL3(t *testing.T) {
	t.Helper()
	bin := os.Getenv("IVORY_OPENSSL3")
	if bin == "" {
		bin = "openssl"
	}
	skip := t.Skipf
	if os.Getenv("IVORY_REQUIRE_TLS13") != "" {
		skip = t.Fatalf
	}
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		skip("%s: %v", bin, err)
		return
	}
	m := regexp.MustCompile(`^OpenSSL (\d+)\.(\d+)\.`).FindSubmatch(out)
	if m == nil {
		skip("%s: unexpected version %q", bin, out)
		return
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	if major < 3 || major == 3 && minor < 2 {
		skip("%s is %s; TLS 1.3 with Brainpool needs OpenSSL 3.2 or later (set IVORY_OPENSSL3)", bin, out)
		return
	}
	t.Logf("using %s", out)
	saved := opensslBin
	opensslBin = bin
	t.Cleanup(func() { opensslBin = saved })
}

// schemeRecorder wraps tlsutil.VerifyUnsupportedSignature and records the
// signature schemes it gets.
type schemeRecorder struct {
	mu      sync.Mutex
	schemes []tls.SignatureScheme
}

func (r *schemeRecorder) verify(leaf *x509.Certificate, scheme tls.SignatureScheme, signed, sig []byte) error {
	r.mu.Lock()
	r.schemes = append(r.schemes, scheme)
	r.mu.Unlock()
	return tlsutil.VerifyUnsupportedSignature(leaf, scheme, signed, sig)
}

func (r *schemeRecorder) get() []tls.SignatureScheme {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]tls.SignatureScheme(nil), r.schemes...)
}

// tls13Config turns a config from brainpoolServer or brainpoolClient into
// a TLS 1.3 config: TLS 1.3 only, the Brainpool groups of the curves, the
// signature schemes of tlsutil.SignatureSchemes, and a recording hook.
func tls13Config(config *tls.Config, r *schemeRecorder, curves ...brainpool.Curve) *tls.Config {
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.KeyExchanges = tlsutil.KeyExchanges(curves...)
	config.CurvePreferences = nil
	config.SignatureSchemes = tlsutil.SignatureSchemes()
	config.VerifyUnsupportedSignature = r.verify
	return config
}

func checkTLS13(t *testing.T, cs tls.ConnectionState, wantCN string, wantCurve tls.CurveID, wantHRR bool) {
	t.Helper()
	if cs.Version != tls.VersionTLS13 {
		t.Errorf("version = %x, want TLS 1.3", cs.Version)
	}
	if cs.CurveID != wantCurve {
		t.Errorf("group = %v, want %v", curveName(cs.CurveID), curveName(wantCurve))
	}
	if cs.HelloRetryRequest != wantHRR {
		t.Errorf("HelloRetryRequest = %v, want %v", cs.HelloRetryRequest, wantHRR)
	}
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != wantCN {
		t.Errorf("peer certificates = %v, want CN %q", cs.PeerCertificates, wantCN)
	}
}

func checkSchemes(t *testing.T, who string, got []tls.SignatureScheme, want tls.SignatureScheme) {
	t.Helper()
	if len(got) != 1 || got[0] != want {
		t.Errorf("%s verified signature schemes %v, want [%v]", who, got, want)
	}
}

var tls13Curves = []struct {
	bits   string
	curve  brainpool.Curve
	group  tls.CurveID
	scheme tls.SignatureScheme
	name   string // OpenSSL's group name
	sig    string // OpenSSL's signature scheme name
}{
	{"256", brainpool.P256r1(), tlsutil.CurveBrainpoolP256r1TLS13, tlsutil.ECDSABrainpoolP256r1TLS13SHA256, "brainpoolP256r1tls13", "ecdsa_brainpoolP256r1tls13_sha256"},
	{"384", brainpool.P384r1(), tlsutil.CurveBrainpoolP384r1TLS13, tlsutil.ECDSABrainpoolP384r1TLS13SHA384, "brainpoolP384r1tls13", "ecdsa_brainpoolP384r1tls13_sha384"},
	{"512", brainpool.P512r1(), tlsutil.CurveBrainpoolP512r1TLS13, tlsutil.ECDSABrainpoolP512r1TLS13SHA512, "brainpoolP512r1tls13", "ecdsa_brainpoolP512r1tls13_sha512"},
}

// I13: Go client and Go server in TLS 1.3, mutual authentication with
// Brainpool certificates, Brainpool groups only (a key share for 31-33 in
// the first ClientHello).
func TestI13GoGoTLS13(t *testing.T) {
	for _, tt := range tls13Curves {
		t.Run("bp"+tt.bits, func(t *testing.T) {
			var sr, cr schemeRecorder
			server := tls13Config(brainpoolServer(t, "bp"+tt.bits+"-server", "bp"+tt.bits+"-ca"), &sr, tt.curve)
			client := tls13Config(brainpoolClient(t, "bp"+tt.bits+"-client", "bp"+tt.bits+"-ca"), &cr, tt.curve)
			client.CurvePreferences = []tls.CurveID{tt.group}
			scs, ccs, err := goGo(t, client, server)
			if err != nil {
				t.Fatal(err)
			}
			checkTLS13(t, ccs, "localhost", tt.group, false)
			checkTLS13(t, scs, "ivory Brainpool P"+tt.bits+" Client", tt.group, false)
			checkSchemes(t, "client", cr.get(), tt.scheme)
			checkSchemes(t, "server", sr.get(), tt.scheme)
		})
	}
}

// I14: HelloRetryRequest. The client offers Go's built-in groups first and
// sends a key share for one of them; the server accepts only
// brainpoolP256r1tls13 and asks for it.
func TestI14HelloRetryRequest(t *testing.T) {
	var sr, cr schemeRecorder
	server := tls13Config(brainpoolServer(t, "bp256-server", "bp256-ca"), &sr, brainpool.P256r1())
	server.CurvePreferences = []tls.CurveID{tlsutil.CurveBrainpoolP256r1TLS13}
	client := tls13Config(brainpoolClient(t, "bp256-client", "bp256-ca"), &cr, brainpool.P256r1())
	scs, ccs, err := goGo(t, client, server)
	if err != nil {
		t.Fatal(err)
	}
	checkTLS13(t, ccs, "localhost", tlsutil.CurveBrainpoolP256r1TLS13, true)
	checkTLS13(t, scs, "ivory Brainpool P256 Client", tlsutil.CurveBrainpoolP256r1TLS13, true)

	// tlsutil.GetCertificate picks the Brainpool identity in TLS 1.3
	// although the client doesn't list group 26, which only TLS 1.2
	// requires, and the RSA identity for a client without 0x081A.
	t.Run("GetCertificate", func(t *testing.T) {
		for _, tt := range []struct {
			name       string
			schemes    []tls.SignatureScheme
			wantIssuer string
		}{
			{"Brainpool scheme", tlsutil.SignatureSchemes(), "ivory Brainpool P256 Test CA"},
			{"no Brainpool scheme", []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256}, "ivory RSA Test CA"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				var sr, cr schemeRecorder
				server := tls13Config(brainpoolServer(t, "bp256-server", "bp256-ca"), &sr, brainpool.P256r1())
				certs := []tls.Certificate{server.Certificates[0], rsaServerKeyPair(t)}
				server.Certificates = nil
				server.GetCertificate = tlsutil.GetCertificate(certs)
				client := tls13Config(brainpoolClient(t, "bp256-client", "bp256-ca"), &cr, brainpool.P256r1())
				client.CurvePreferences = []tls.CurveID{tlsutil.CurveBrainpoolP256r1TLS13}
				client.SignatureSchemes = tt.schemes
				client.VerifyConnection = nil // the RSA server has another CA
				_, ccs, err := goGo(t, client, server)
				if err != nil {
					t.Fatal(err)
				}
				if cn := ccs.PeerCertificates[0].Issuer.CommonName; cn != tt.wantIssuer {
					t.Errorf("server certificate issuer = %q, want %q", cn, tt.wantIssuer)
				}
			})
		}
	})
}

// rsaServerKeyPair loads the RSA server identity of the test PKI.
func rsaServerKeyPair(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(pkiFile("rsa-server.pem"), pkiFile("rsa-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func sServerArgs13(bits, groups string) []string {
	return []string{"-tls1_3", "-groups", groups,
		"-cert", pkiFile("bp" + bits + "-server.pem"), "-key", pkiFile("bp" + bits + "-server.key"),
		"-Verify", "1", "-CAfile", pkiFile("bp" + bits + "-ca.pem"), "-verify_return_error"}
}

func sClientArgs13(bits, groups string) []string {
	return []string{"-tls1_3", "-groups", groups,
		"-CAfile", pkiFile("bp" + bits + "-ca.pem"), "-verify_return_error",
		"-cert", pkiFile("bp" + bits + "-client.pem"), "-key", pkiFile("bp" + bits + "-client.key")}
}

// I15: Go client with a Brainpool client certificate against OpenSSL
// s_server with a Brainpool certificate in TLS 1.3, on all three curves.
// With the Go client's default group order, its first key share is for a
// built-in group, and s_server asks for the Brainpool group.
func TestI15GoClientOpenSSLServerTLS13(t *testing.T) {
	useOpenSSL3(t)
	for _, tt := range tls13Curves {
		for _, hrr := range []bool{false, true} {
			name := "bp" + tt.bits
			if hrr {
				name += "/HelloRetryRequest"
			}
			t.Run(name, func(t *testing.T) {
				var cr schemeRecorder
				config := tls13Config(brainpoolClient(t, "bp"+tt.bits+"-client", "bp"+tt.bits+"-ca"), &cr, tt.curve)
				if !hrr {
					config.CurvePreferences = []tls.CurveID{tt.group}
				}
				cs, out, err := clientWithSServer(t, config, sServerArgs13(tt.bits, tt.name)...)
				if err != nil {
					t.Fatal(err)
				}
				checkTLS13(t, cs, "localhost", tt.group, hrr)
				checkSchemes(t, "client", cr.get(), tt.scheme)
				wantOutput(t, out, "subject=CN=ivory Brainpool P"+tt.bits+" Client",
					"Peer signature type: "+tt.sig, "Shared groups: "+tt.name)
			})
		}
	}
}

// I16: Go server with a Brainpool certificate requiring a client
// certificate, against OpenSSL s_client with a Brainpool certificate in
// TLS 1.3. For the HelloRetryRequest case, s_client sends a key share for
// X25519 first and the Go server accepts only the Brainpool group.
func TestI16GoServerOpenSSLClientTLS13(t *testing.T) {
	useOpenSSL3(t)
	for _, tt := range tls13Curves {
		for _, hrr := range []bool{false, true} {
			name := "bp" + tt.bits
			groups := tt.name
			if hrr {
				name += "/HelloRetryRequest"
				groups = "X25519:" + tt.name
			}
			t.Run(name, func(t *testing.T) {
				var sr schemeRecorder
				config := tls13Config(brainpoolServer(t, "bp"+tt.bits+"-server", "bp"+tt.bits+"-ca"), &sr, tt.curve)
				config.CurvePreferences = []tls.CurveID{tt.group}
				cs, out, err := serverWithSClient(t, config, sClientArgs13(tt.bits, groups)...)
				if err != nil {
					t.Fatal(err)
				}
				checkTLS13(t, cs, "ivory Brainpool P"+tt.bits+" Client", tt.group, hrr)
				checkSchemes(t, "server", sr.get(), tt.scheme)
				wantOutput(t, out, "Verification: OK", "Protocol: TLSv1.3",
					"Peer signature type: "+tt.sig, "Peer Temp Key: ECDH, brainpoolP"+tt.bits+"r1")
			})
		}
	}
}
