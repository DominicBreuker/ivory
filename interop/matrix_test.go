//go:build ivory

package interop

// The interop matrix (README.md), part two: I5, I6 and I8-I12. I6, I10,
// I11 and I12 use the ti presets.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
)

// I5: I1-I3 with brainpoolP384r1 and brainpoolP512r1.
func TestI5OtherCurves(t *testing.T) {
	for _, tt := range []struct {
		bits  string
		curve brainpool.Curve
		group tls.CurveID
		name  string
	}{
		{"384", brainpool.P384r1(), tlsutil.CurveBrainpoolP384r1, "brainpoolP384r1"},
		{"512", brainpool.P512r1(), tlsutil.CurveBrainpoolP512r1, "brainpoolP512r1"},
	} {
		bp := "bp" + tt.bits
		clientArgs := func(groups string) []string {
			return []string{"-tls1_2", "-groups", groups, "-CAfile", pkiFile(bp + "-ca.pem"), "-verify_return_error",
				"-cert", pkiFile(bp + "-client.pem"), "-key", pkiFile(bp + "-client.key")}
		}
		cn := "ivory Brainpool P" + tt.bits + " Client"
		t.Run("I1 "+tt.name, func(t *testing.T) {
			config := brainpoolServer(t, bp+"-server", bp+"-ca")
			cs, out, err := serverWithSClient(t, config, clientArgs("P-256:"+tt.name)...)
			if err != nil {
				t.Fatal(err)
			}
			checkPeer(t, cs, cn, tls.CurveP256)
			wantOutput(t, out, "Server Temp Key: ECDH, prime256v1", "Verification: OK", "Peer signature type: ECDSA")
		})
		t.Run("I2 "+tt.name, func(t *testing.T) {
			config := brainpoolServer(t, bp+"-server", bp+"-ca")
			config.KeyExchanges = tlsutil.KeyExchanges(tt.curve)
			cs, out, err := serverWithSClient(t, config, clientArgs(tt.name)...)
			if err != nil {
				t.Fatal(err)
			}
			checkPeer(t, cs, cn, tt.group)
			wantOutput(t, out, "Server Temp Key: ECDH, "+tt.name, "Verification: OK")
		})
		t.Run("I3 "+tt.name, func(t *testing.T) {
			config := brainpoolClient(t, bp+"-client", bp+"-ca")
			config.KeyExchanges = tlsutil.KeyExchanges(tt.curve)
			config.CurvePreferences = []tls.CurveID{tls.CurveP256, tt.group}
			cs, out, err := clientWithSServer(t, config, "-tls1_2", "-groups", tt.name,
				"-cert", pkiFile(bp+"-server.pem"), "-key", pkiFile(bp+"-server.key"),
				"-Verify", "1", "-CAfile", pkiFile(bp+"-ca.pem"), "-verify_return_error")
			if err != nil {
				t.Fatal(err)
			}
			checkPeer(t, cs, "localhost", tt.group)
			wantOutput(t, out, "CN = "+cn, "Peer signature type: ECDSA")
		})
	}
}

// ktConfig returns the ti preset of an eHealth-KT with the Brainpool and
// the RSA test identity, accepting client certificates from bp256-ca.
func ktConfig(t *testing.T) *tls.Config {
	t.Helper()
	ecc := loadKeyPair(t, "bp256-server")
	rsaCert, err := tls.LoadX509KeyPair(pkiFile("rsa-server.pem"), pkiFile("rsa-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	konnektor := ti.KonnektorVerifier([]*x509.Certificate{readCert(t, "bp256-ca")})
	konnektor.Policies = nil // the test PKI has no TI policies
	c, err := (&ti.KTServer{ECC: &ecc, RSA: &rsaCert, Konnektor: konnektor}).Config()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// I6: an eHealth-KT with two identities presents the Brainpool one to a
// client that offers only ECDSA suites, and the RSA one to a client that
// offers only RSA suites (A_22453).
func TestI6TwoIdentities(t *testing.T) {
	for _, tt := range []struct {
		name, cipher, ca string
		wantSuite        uint16
	}{
		{"ECDSA suites", "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384", "bp256-ca", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{"RSA suites", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384", "rsa-ca", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cs, out, err := serverWithSClient(t, ktConfig(t), "-tls1_2", "-cipher", tt.cipher,
				"-groups", "P-256:P-384:brainpoolP256r1:brainpoolP384r1",
				"-CAfile", pkiFile(tt.ca+".pem"), "-verify_return_error")
			if err != nil {
				t.Fatal(err)
			}
			if cs.CipherSuite != tt.wantSuite {
				t.Errorf("cipher suite = %s, want %s", tls.CipherSuiteName(cs.CipherSuite), tls.CipherSuiteName(tt.wantSuite))
			}
			wantOutput(t, out, "Verification: OK")
		})
	}
}

// I8: no SHA-1 signature scheme is used, by a Go server or a Go client,
// even when the peer prefers or offers only SHA-1 (A_21275-01).
func TestI8NoSHA1(t *testing.T) {
	t.Run("server, SHA-1 preferred", func(t *testing.T) {
		config := brainpoolServer(t, "bp256-server", "bp256-ca")
		_, out, err := serverWithSClient(t, config, append(sClientArgs("P-256:brainpoolP256r1"), "-sigalgs", "ECDSA+SHA1:ECDSA+SHA256")...)
		if err != nil {
			t.Fatal(err)
		}
		wantOutput(t, out, "Peer signing digest: SHA256", "Peer signature type: ECDSA")
	})
	t.Run("server, only SHA-1", func(t *testing.T) {
		config := brainpoolServer(t, "bp256-server", "bp256-ca")
		_, _, err := serverWithSClient(t, config, append(sClientArgs("P-256:brainpoolP256r1"), "-sigalgs", "ECDSA+SHA1")...)
		if err == nil {
			t.Fatal("handshake succeeded with only SHA-1 signatures")
		}
	})
	t.Run("client, only SHA-1", func(t *testing.T) {
		config := brainpoolClient(t, "bp256-client", "bp256-ca")
		_, _, err := clientWithSServer(t, config, append(sServerArgs("P-256:brainpoolP256r1"), "-client_sigalgs", "ECDSA+SHA1")...)
		if err == nil {
			t.Fatal("client signed with SHA-1")
		}
	})
}

// I9: a Go server refuses a renegotiation from OpenSSL with a fatal
// no_renegotiation alert (GS-A_5524, P0; probe K5).
func TestI9Renegotiation(t *testing.T) {
	needOpenSSL(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(opTimeout))
		c := tls.Server(conn, brainpoolServer(t, "bp256-server", "bp256-ca"))
		if err := c.Handshake(); err != nil {
			serverErr <- err
			return
		}
		io.WriteString(c, greeting+"\n")
		_, err = io.Copy(io.Discard, c)
		if err == nil {
			err = errors.New("connection closed without an error")
		}
		serverErr <- err
	}()
	p := startOpenSSL(t, append([]string{"s_client", "-connect", ln.Addr().String(), "-msg"}, sClientArgs("P-256:brainpoolP256r1")...)...)
	if !p.waitFor(greeting) {
		t.Fatalf("no greeting:\n%s", p.stop())
	}
	io.WriteString(p.stdin, "R\n")
	var serr error
	select {
	case serr = <-serverErr:
	case <-time.After(opTimeout):
		t.Fatal("timeout waiting for the server")
	}
	p.waitFor("no_renegotiation")
	out := p.stop()
	if serr == nil || !strings.Contains(serr.Error(), "no renegotiation") {
		t.Errorf("server error = %v, want no renegotiation", serr)
	}
	wantOutput(t, out, "RENEGOTIATING", "fatal no_renegotiation")
}

// certificateTypes returns the certificate_types of the CertificateRequest
// in the output of openssl s_client -msg.
func certificateTypes(t *testing.T, out string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "<<< TLS 1.2, Handshake") && strings.HasSuffix(strings.TrimSpace(l), "CertificateRequest") && i+1 < len(lines) {
			b := strings.Fields(lines[i+1]) // 0d, length (3 bytes), count, types...
			if len(b) < 5 {
				break
			}
			n, err := strconv.ParseUint(b[4], 16, 8)
			if err == nil && 5+int(n) <= len(b) {
				return strings.Join(b[5:5+int(n)], " ")
			}
		}
	}
	t.Fatalf("no CertificateRequest in the output:\n%s", out)
	return ""
}

// I10: the CertificateRequest of an eHealth-KT has one certificate type,
// the one that matches the suite (A_22454, P6, profile kt; probe K3).
func TestI10CertificateTypes(t *testing.T) {
	for _, tt := range []struct {
		name, cipher, ca string
		wantKT           string
	}{
		{"ECDSA suite", "ECDHE-ECDSA-AES128-GCM-SHA256", "bp256-ca", "40"},
		{"RSA suite", "ECDHE-RSA-AES128-GCM-SHA256", "rsa-ca", "01"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, out, err := serverWithSClient(t, ktConfig(t), "-tls1_2", "-msg", "-cipher", tt.cipher,
				"-groups", "P-256:brainpoolP256r1", "-CAfile", pkiFile(tt.ca+".pem"), "-verify_return_error")
			if err != nil {
				t.Fatal(err)
			}
			want := "01 40" // core: rsa_sign, ecdsa_sign
			if ktProfile {
				want = tt.wantKT
			}
			if got := certificateTypes(t, out); got != want {
				t.Errorf("certificate_types = %s, want %s", got, want)
			}
		})
	}
}

// connectorConfig returns the ti preset of a Konnektor-like client with
// the Brainpool test identity, trusting terminals from bp256-ca.
func connectorConfig(t *testing.T) *tls.Config {
	t.Helper()
	kt := &ti.Verifier{CAs: []*x509.Certificate{readCert(t, "bp256-ca")}}
	return ti.ConnectorClientConfig(loadKeyPair(t, "bp256-client"), kt)
}

// connectorWithSServer runs the ti Konnektor preset against openssl
// s_server and returns s_server's output.
func connectorWithSServer(t *testing.T) string {
	t.Helper()
	_, out, err := clientWithSServer(t, connectorConfig(t), sServerArgs("P-256:P-384:brainpoolP256r1:brainpoolP384r1")...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// I11: a Konnektor-like client (ti preset) offers the ECDSA suites first
// with the profile kt (A_17124-03 item 3, A_17094-02, P7; probe K1).
func TestI11SuiteOrder(t *testing.T) {
	out := connectorWithSServer(t)
	want := "Shared ciphers:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
	if ktProfile {
		want = "Shared ciphers:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
	}
	wantOutput(t, out, want)
}

// I12: the ti presets offer exactly the TI groups P-256, P-384,
// brainpoolP256r1 and brainpoolP384r1 (GS-A_4384-03; probe K4).
func TestI12SupportedGroups(t *testing.T) {
	out := connectorWithSServer(t)
	wantOutput(t, out, "Supported groups: secp256r1:secp384r1:brainpoolP256r1:brainpoolP384r1\n")
}
