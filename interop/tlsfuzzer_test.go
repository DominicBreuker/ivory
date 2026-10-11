//go:build ivory

package interop

// tlsfuzzer (https://github.com/tlsfuzzer/tlsfuzzer) against ivory
// servers: F1-F6. tlsfuzzer sends hand-crafted and malformed handshakes
// and checks the server's answers and alerts. Where ivory deliberately
// differs from what a script expects, the probe is listed as an expected
// failure (-x) with the message it must fail with (-X), so that a change
// in either direction fails the test. The tests need a tlsfuzzer
// checkout and a Python with tlslite-ng in the directory $IVORY_TLSFUZZER
// (scripts/fetch-tlsfuzzer.sh). They are skipped without it, unless
// $IVORY_REQUIRE_TLSFUZZER is set (the CI job tlsfuzzer).

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
)

// needTLSFuzzer returns the Python interpreter and the tlsfuzzer checkout
// in $IVORY_TLSFUZZER. It skips the test if they are missing, or fails it
// if $IVORY_REQUIRE_TLSFUZZER is set.
func needTLSFuzzer(t *testing.T) (python, dir string) {
	t.Helper()
	skip := t.Skipf
	if os.Getenv("IVORY_REQUIRE_TLSFUZZER") != "" {
		skip = t.Fatalf
	}
	root := os.Getenv("IVORY_TLSFUZZER")
	if root == "" {
		skip("IVORY_TLSFUZZER is not set (scripts/fetch-tlsfuzzer.sh)")
		return
	}
	python = filepath.Join(root, "venv", "bin", "python")
	dir = filepath.Join(root, "tlsfuzzer")
	for _, f := range []string{python, filepath.Join(dir, "scripts")} {
		if _, err := os.Stat(f); err != nil {
			skip("%v (scripts/fetch-tlsfuzzer.sh)", err)
			return
		}
	}
	return python, dir
}

// absPKI returns the absolute path of a file of the test PKI, for
// scripts that run in another directory.
func absPKI(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(pkiFile(name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fuzzServer serves config on a local port until the test ends, like
// "openssl s_server -www": it answers every request with a short HTTP
// response and closes the connection after the client's close_notify. It
// returns the port and a function that reports the handshake errors seen.
func fuzzServer(t *testing.T, config *tls.Config) (port int, errs func() []string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu     sync.Mutex
		failed []string
		wg     sync.WaitGroup
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(30 * time.Second))
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					mu.Lock()
					failed = append(failed, err.Error())
					mu.Unlock()
					return
				}
				r := bufio.NewReader(tc)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				io.WriteString(tc, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nivory\r\n")
				io.Copy(io.Discard, tc) // until the client's close_notify
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	return ln.Addr().(*net.TCPAddr).Port, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), failed...)
	}
}

// runTLSFuzzer runs a tlsfuzzer script against port with args and fails
// the test if the script fails. It logs the script's summary.
func runTLSFuzzer(t *testing.T, port int, script string, args ...string) {
	t.Helper()
	python, dir := needTLSFuzzer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, append([]string{filepath.Join(dir, "scripts", script), "-p", strconv.Itoa(port)}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if i := strings.LastIndex(string(out), "Test end"); i >= 0 {
		t.Logf("%s:\n%s", script, out[i:])
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Errorf("%s failed (%v):\n%s", script, err, out)
			return
		}
		t.Fatal(err)
	}
}

// xfail returns the tlsfuzzer arguments that expect probe to fail with
// msg in its error.
func xfail(probe, msg string) []string { return []string{"-x", probe, "-X", msg} }

var fuzzCurves = []brainpool.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1()}

// fuzzServer12 is a TLS 1.2 server with the Brainpool identity
// bp<bits>-server and all Brainpool groups. With clientCA it asks for a
// client certificate and checks one if sent (some probes send none).
func fuzzServer12(t *testing.T, bits string, clientCA bool) *tls.Config {
	c := &tls.Config{
		MinVersion:                 tls.VersionTLS12,
		MaxVersion:                 tls.VersionTLS12,
		Certificates:               []tls.Certificate{loadKeyPair(t, "bp"+bits+"-server")},
		VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
		KeyExchanges:               tlsutil.KeyExchanges(fuzzCurves...),
	}
	if clientCA {
		v := &tlsutil.ChainVerifier{
			Roots:    []*x509.Certificate{readCert(t, "bp"+bits+"-ca")},
			KeyUsage: x509.ExtKeyUsageClientAuth,
		}
		c.ClientAuth = tls.RequestClientCert
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return nil
			}
			return v.VerifyConnection(cs)
		}
	}
	return c
}

// sigFlexibilityXfail are the expected failures of
// test-ecdsa-sig-flexibility.py: a client that offers only SHA-1 or
// SHA-224 with ECDSA gets handshake_failure (SHA-1 is never used,
// A_21275-01; crypto/tls has no SHA-224). A TLS 1.2 client that offers
// only a TLS 1.3 Brainpool scheme is refused too, but crypto/tls picks
// the signature scheme when it writes ServerKeyExchange, so the alert
// comes after ServerHello, not instead of it.
func sigFlexibilityXfail() []string {
	var args []string
	for _, h := range []string{"sha1", "sha224"} {
		args = append(args, xfail("connect with "+h+"+ecdsa only", "Alert(fatal, handshake_failure)")...)
	}
	for _, s := range []string{"ecdsa_brainpoolP256r1tls13_sha256", "ecdsa_brainpoolP384r1tls13_sha384", "ecdsa_brainpoolP512r1tls13_sha512"} {
		args = append(args, xfail("connect with "+s+" only", "Handshake(server_hello)")...)
	}
	return args
}

// F1: malformed TLS 1.3 key shares on the Brainpool groups 31-33 (padded,
// truncated, from another curve, the point at infinity, off the curve,
// x = y = 0) end with illegal_parameter.
//
// With tlsutil.TLS12Fallback on a server for TLS 1.2 and 1.3, the same
// script still gets TLS 1.3: an RFC 8734 client never falls back.
func TestF1TLS13BrainpoolKeyShares(t *testing.T) {
	needTLSFuzzer(t)
	t.Run("TLS 1.3", func(t *testing.T) {
		var r schemeRecorder
		c := tls13Config(fuzzServer12(t, "256", false), &r, fuzzCurves...)
		port, _ := fuzzServer(t, c)
		runTLSFuzzer(t, port, "test-tls13-ecdhe-brainpool-curves.py")
	})
	t.Run("TLS 1.2 and 1.3 with TLS12Fallback", func(t *testing.T) {
		var r schemeRecorder
		c := tls13Config(fuzzServer12(t, "256", false), &r, fuzzCurves...)
		c.MinVersion = tls.VersionTLS12
		c.GetConfigForClient = tlsutil.TLS12Fallback(c, nil)
		port, _ := fuzzServer(t, c)
		runTLSFuzzer(t, port, "test-tls13-ecdhe-brainpool-curves.py")
	})
}

// tls13CertRequestSchemes are the signature schemes of a TLS 1.3
// CertificateRequest of a server with tlsutil.SignatureSchemes.
const tls13CertRequestSchemes = "rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 " +
	"ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512 " +
	"ecdsa_brainpoolP256r1tls13_sha256 ecdsa_brainpoolP384r1tls13_sha384 ecdsa_brainpoolP512r1tls13_sha512"

// F2: TLS 1.3 client authentication with Brainpool certificates: the
// scheme of the key's curve works; fuzzed signatures, TLS 1.2-only
// schemes and the NIST schemes are refused. A Brainpool scheme of another
// curve than the key's is refused with decrypt_error, where tlsfuzzer
// expects illegal_parameter: crypto/tls refuses a NIST key's mismatch
// before it verifies (illegal_parameter), but leaves Brainpool keys to
// Config.VerifyUnsupportedSignature, whose errors end with decrypt_error.
func TestF2TLS13BrainpoolCertificateVerify(t *testing.T) {
	needTLSFuzzer(t)
	for _, tt := range tls13Curves {
		t.Run(tt.bits, func(t *testing.T) {
			var r schemeRecorder
			c := tls13Config(fuzzServer12(t, tt.bits, true), &r, fuzzCurves...)
			port, _ := fuzzServer(t, c)
			args := []string{"-k", absPKI(t, "bp"+tt.bits+"-client.sec1.pem"), "-c", absPKI(t, "bp"+tt.bits+"-client.pem"),
				"-s", tls13CertRequestSchemes}
			for _, other := range tls13Curves {
				if other.bits != tt.bits {
					args = append(args, xfail("check "+other.sig+" signature is refused", `received "decrypt_error"`)...)
				}
			}
			runTLSFuzzer(t, port, "test-tls13-ecdsa-brainpool-in-certificate-verify.py", args...)
		})
	}
}

// F3: TLS 1.2 servers with Brainpool identities sign ServerKeyExchange
// with the hash the client asks for (SHA-256, -384, -512), also the TI
// server preset ti.ServerConfig on an AES-GCM suite.
func TestF3ECDSASignatureFlexibility(t *testing.T) {
	needTLSFuzzer(t)
	for _, bits := range []string{"256", "384", "512"} {
		t.Run(bits, func(t *testing.T) {
			port, _ := fuzzServer(t, fuzzServer12(t, bits, false))
			runTLSFuzzer(t, port, "test-ecdsa-sig-flexibility.py", append([]string{"-g", "secp256r1:brainpoolP" + bits + "r1"}, sigFlexibilityXfail()...)...)
		})
	}
	t.Run("ti.ServerConfig", func(t *testing.T) {
		port, _ := fuzzServer(t, ti.ServerConfig([]tls.Certificate{loadKeyPair(t, "bp256-server")}, nil))
		runTLSFuzzer(t, port, "test-ecdsa-sig-flexibility.py", append([]string{"-g", "secp256r1:brainpoolP256r1",
			"-C", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, sigFlexibilityXfail()...)...)
	})
}

// F4: TLS 1.2 client authentication with Brainpool certificates: ECDSA
// with SHA-256, -384 and -512 works, MD5 and mismatched hashes are
// refused. A CertificateVerify that names SHA-1 or SHA-224 is refused
// with illegal_parameter, since the server never offers them
// (A_21275-01); tlsfuzzer expects them to work or to fail with
// decrypt_error.
func TestF4TLS12CertificateVerify(t *testing.T) {
	needTLSFuzzer(t)
	var args []string
	for _, h := range []string{"sha512", "sha384", "sha256", "sha224", "sha1"} {
		for _, adv := range []string{"sha224", "sha1"} {
			name := fmt.Sprintf("make %s+ecdsa signature, advertise it as %s+ecdsa in CertificateVerify", h, adv)
			if h == adv {
				name = fmt.Sprintf("make %s+ecdsa signature in CertificateVerify", h)
			}
			args = append(args, xfail(name, "illegal_parameter")...)
		}
	}
	for _, bits := range []string{"256", "384", "512"} {
		t.Run(bits, func(t *testing.T) {
			port, _ := fuzzServer(t, fuzzServer12(t, bits, true))
			runTLSFuzzer(t, port, "test-ecdsa-in-certificate-verify.py", append([]string{"-n", "0",
				"-k", absPKI(t, "bp"+bits+"-client.sec1.pem"), "-c", absPKI(t, "bp"+bits+"-client.pem"),
				"-g", "secp256r1:brainpoolP" + bits + "r1"}, args...)...)
		})
	}
}

// F5: a TLS 1.3 server with brainpoolP256r1, P384r1, P512r1 and P-256
// identities (tlsutil.GetCertificate) answers a client that offers one
// signature scheme with the matching identity; SHA-1 and SHA-224 fail.
// The test PKI has no P-384 or P-521 identity.
func TestF5TLS13ServerCertificates(t *testing.T) {
	needTLSFuzzer(t)
	var certs []tls.Certificate
	for _, name := range []string{"bp256-server", "bp384-server", "bp512-server"} {
		certs = append(certs, loadKeyPair(t, name))
	}
	p256, err := tls.LoadX509KeyPair(pkiFile("p256-under-bp256.pem"), pkiFile("p256-under-bp256.key"))
	if err != nil {
		t.Fatal(err)
	}
	c := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		GetCertificate:   tlsutil.GetCertificate(append(certs, p256)),
		KeyExchanges:     tlsutil.KeyExchanges(fuzzCurves...),
		SignatureSchemes: tlsutil.SignatureSchemes(),
	}
	port, _ := fuzzServer(t, c)
	runTLSFuzzer(t, port, "test-tls13-ecdsa-support.py",
		"-e", "Test with ecdsa_secp384r1_sha384", "-e", "Test with ecdsa_secp521r1_sha512")
}

// tls12CertRequestSchemes are the signature schemes of crypto/tls's TLS
// 1.2 CertificateRequest: no SHA-1 (A_21275-01).
const tls12CertRequestSchemes = "rsa_pss_rsae_sha256 ecdsa_secp256r1_sha256 ed25519 " +
	"rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512 " +
	"ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512"

// tls12CertRequestSchemesECDSA are those of profile kt's CertificateRequest
// on an ECDSA suite: only the schemes of ecdsa_sign, Ed25519 included
// (RFC 8422, Section 5.5).
const tls12CertRequestSchemesECDSA = "ecdsa_secp256r1_sha256 ed25519 ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512"

// F6: the CertificateRequest of the KT server (ti.KTServer) on an ECDSA
// suite, with a Konnektor-like Brainpool client certificate. Profile
// core asks for rsa_sign and ecdsa_sign with all of crypto/tls's schemes.
// Profile kt asks only for ecdsa_sign, the type of the suite (A_22454),
// and lists only its schemes, so that tlsfuzzer's consistency check
// passes.
func TestF6KTCertificateRequest(t *testing.T) {
	needTLSFuzzer(t)
	port, _ := fuzzServer(t, ktConfig(t))
	schemes, types := tls12CertRequestSchemes, "rsa_sign ecdsa_sign"
	if ktProfile {
		schemes, types = tls12CertRequestSchemesECDSA, "ecdsa_sign"
	}
	runTLSFuzzer(t, port, "test-certificate-request.py", "-d", "-C", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"-k", absPKI(t, "bp256-client.sec1.pem"), "-c", absPKI(t, "bp256-client.pem"),
		"-s", schemes, "-T", types)
}
