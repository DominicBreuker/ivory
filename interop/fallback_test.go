//go:build ivory

package interop

import (
	"crypto/tls"
	"os/exec"
	"regexp"
	"strconv"
	"testing"

	"github.com/DominicBreuker/ivory/tlsutil"
)

// opensslVersion returns the major and minor version of opensslBin.
func opensslVersion(t *testing.T) (major, minor int) {
	t.Helper()
	out, err := exec.Command(opensslBin, "version").Output()
	if err != nil {
		t.Skipf("%s: %v", opensslBin, err)
	}
	m := regexp.MustCompile(`^OpenSSL (\d+)\.(\d+)\.`).FindSubmatch(out)
	if m == nil {
		t.Skipf("%s: unexpected version %q", opensslBin, out)
	}
	major, _ = strconv.Atoi(string(m[1]))
	minor, _ = strconv.Atoi(string(m[2]))
	return major, minor
}

// fallbackServerConfig is a Go server for TLS 1.2 and 1.3 with the
// identity bp256-server, all Brainpool groups and schemes, and, if
// fallback is set, tlsutil.TLS12Fallback. *used reports whether the
// fallback chose TLS 1.2.
func fallbackServerConfig(t *testing.T, fallback bool, used *bool) *tls.Config {
	c := brainpoolServer(t, "bp256-server", "bp256-ca")
	c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS13
	c.KeyExchanges = tlsutil.KeyExchanges(fuzzCurves...)
	c.SignatureSchemes = tlsutil.SignatureSchemes()
	if fallback {
		next := tlsutil.TLS12Fallback(c, nil)
		c.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			config, err := next(chi)
			*used = config != nil
			return config, err
		}
	}
	return c
}

// I17: tlsutil.TLS12Fallback. OpenSSL before 3.2 offers TLS 1.3 but the
// Brainpool groups only as 26-28 and no Brainpool scheme for TLS 1.3,
// like Windows SChannel (S5): a Go server for TLS 1.2 and 1.3 with only a
// Brainpool identity fails the handshake, and with the fallback answers in
// TLS 1.2. OpenSSL 3.2 and later is an RFC 8734 client and keeps TLS 1.3
// with the fallback on.
func TestI17TLS12Fallback(t *testing.T) {
	t.Run("OpenSSL before 3.2", func(t *testing.T) {
		needOpenSSL(t)
		if major, minor := opensslVersion(t); major > 3 || major == 3 && minor >= 2 {
			t.Skipf("%s is %d.%d, an RFC 8734 client", opensslBin, major, minor)
		}
		args := []string{"-groups", "brainpoolP256r1:P-256",
			"-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error",
			"-cert", pkiFile("bp256-client.pem"), "-key", pkiFile("bp256-client.key")}
		var used bool
		if _, _, err := serverWithSClient(t, fallbackServerConfig(t, false, &used), args...); err == nil {
			t.Error("without the fallback: handshake succeeded, want a failure")
		}
		cs, out, err := serverWithSClient(t, fallbackServerConfig(t, true, &used), args...)
		if err != nil {
			t.Fatalf("with the fallback: %v\n%s", err, out)
		}
		if !used || cs.Version != tls.VersionTLS12 {
			t.Errorf("fallback used %v, %s; want TLS 1.2", used, tls.VersionName(cs.Version))
		}
		checkPeer(t, cs, "ivory Brainpool P256 Client", tlsutil.CurveBrainpoolP256r1)
		wantOutput(t, out, "Protocol  : TLSv1.2", "Verification: OK")
	})
	t.Run("OpenSSL 3.2 and later", func(t *testing.T) {
		useOpenSSL3(t)
		args := []string{"-groups", "brainpoolP256r1tls13:brainpoolP256r1:P-256",
			"-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error",
			"-cert", pkiFile("bp256-client.pem"), "-key", pkiFile("bp256-client.key")}
		var used bool
		cs, out, err := serverWithSClient(t, fallbackServerConfig(t, true, &used), args...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if used || cs.Version != tls.VersionTLS13 {
			t.Errorf("fallback used %v, %s; want TLS 1.3", used, tls.VersionName(cs.Version))
		}
		checkTLS13(t, cs, "ivory Brainpool P256 Client", tlsutil.CurveBrainpoolP256r1TLS13, false)
	})
}
