//go:build ivory

package interop

// The interop matrix (README.md): I1-I4 and I7 here; I5, I6 and I8-I12
// in matrix_test.go; I13-I16 in tls13_test.go.

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/tlsutil"
)

// tiCurves are the groups of GS-A_4384-03: P-256, P-384, brainpoolP256r1
// and brainpoolP384r1.
var tiCurves = []tls.CurveID{tls.CurveP256, tls.CurveP384, tlsutil.CurveBrainpoolP256r1, tlsutil.CurveBrainpoolP384r1}

func loadKeyPair(t *testing.T, name string) tls.Certificate {
	t.Helper()
	cert, err := tlsutil.LoadX509KeyPair(pkiFile(name+".pem"), pkiFile(name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// brainpoolServer returns a TLS 1.2 server config with a Brainpool
// identity that requires a client certificate from root.
func brainpoolServer(t *testing.T, identity, root string) *tls.Config {
	return &tls.Config{
		MinVersion:                 tls.VersionTLS12,
		MaxVersion:                 tls.VersionTLS12,
		Certificates:               []tls.Certificate{loadKeyPair(t, identity)},
		ClientAuth:                 tls.RequireAnyClientCert,
		VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
		VerifyConnection: (&tlsutil.ChainVerifier{
			Roots:    []*x509.Certificate{readCert(t, root)},
			KeyUsage: x509.ExtKeyUsageClientAuth,
		}).VerifyConnection,
	}
}

// brainpoolClient returns a TLS 1.2 client config with a Brainpool client
// certificate that trusts root, and offers the TI groups.
func brainpoolClient(t *testing.T, identity, root string) *tls.Config {
	return &tls.Config{
		MinVersion:                 tls.VersionTLS12,
		MaxVersion:                 tls.VersionTLS12,
		ServerName:                 "localhost",
		Certificates:               []tls.Certificate{loadKeyPair(t, identity)},
		InsecureSkipVerify:         true, // verified by the ChainVerifier
		VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
		VerifyConnection: (&tlsutil.ChainVerifier{
			Roots:    []*x509.Certificate{readCert(t, root)},
			KeyUsage: x509.ExtKeyUsageServerAuth,
		}).VerifyConnection,
		CurvePreferences: tiCurves,
		KeyExchanges:     tlsutil.KeyExchanges(brainpool.P256r1(), brainpool.P384r1()),
	}
}

func sClientArgs(groups string) []string {
	return []string{"-tls1_2", "-groups", groups,
		"-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error",
		"-cert", pkiFile("bp256-client.pem"), "-key", pkiFile("bp256-client.key")}
}

func sServerArgs(groups string) []string {
	return []string{"-tls1_2", "-groups", groups,
		"-cert", pkiFile("bp256-server.pem"), "-key", pkiFile("bp256-server.key"),
		"-Verify", "1", "-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error"}
}

func checkPeer(t *testing.T, cs tls.ConnectionState, wantCN string, wantCurve tls.CurveID) {
	t.Helper()
	if cs.Version != tls.VersionTLS12 {
		t.Errorf("version = %x, want TLS 1.2", cs.Version)
	}
	if cs.CurveID != wantCurve {
		t.Errorf("group = %v, want %v", curveName(cs.CurveID), curveName(wantCurve))
	}
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != wantCN {
		t.Errorf("peer certificates = %v, want CN %q", cs.PeerCertificates, wantCN)
	}
	if s := tls.CipherSuiteName(cs.CipherSuite); !strings.HasPrefix(s, "TLS_ECDHE_ECDSA_") {
		t.Errorf("cipher suite = %s, want ECDHE_ECDSA", s)
	}
}

func wantOutput(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(out, l) {
			t.Errorf("OpenSSL output lacks %q", l)
		}
	}
}

// I1: Go server with a Brainpool certificate requiring a client
// certificate; OpenSSL client with a Brainpool certificate that offers
// P-256 and brainpoolP256r1. The server needs no KeyExchanges (see interop/h4).
func TestI1GoServerOpenSSLClient(t *testing.T) {
	config := brainpoolServer(t, "bp256-server", "bp256-ca")
	cs, out, err := serverWithSClient(t, config, sClientArgs("P-256:brainpoolP256r1")...)
	if err != nil {
		t.Fatal(err)
	}
	checkPeer(t, cs, "ivory Brainpool P256 Client", tls.CurveP256)
	wantOutput(t, out, "Server Temp Key: ECDH, prime256v1", "Verification: OK", "Peer signature type: ECDSA")
}

// I2: as I1, but the OpenSSL client offers only brainpoolP256r1.
func TestI2GoServerOpenSSLClientBrainpoolGroup(t *testing.T) {
	t.Run("KeyExchanges", func(t *testing.T) {
		config := brainpoolServer(t, "bp256-server", "bp256-ca")
		config.KeyExchanges = tlsutil.KeyExchanges(brainpool.P256r1(), brainpool.P384r1())
		cs, out, err := serverWithSClient(t, config, sClientArgs("brainpoolP256r1")...)
		if err != nil {
			t.Fatal(err)
		}
		checkPeer(t, cs, "ivory Brainpool P256 Client", tlsutil.CurveBrainpoolP256r1)
		wantOutput(t, out, "Server Temp Key: ECDH, brainpoolP256r1", "Verification: OK")
	})
	t.Run("no KeyExchanges", func(t *testing.T) {
		config := brainpoolServer(t, "bp256-server", "bp256-ca")
		_, _, err := serverWithSClient(t, config, sClientArgs("brainpoolP256r1")...)
		if err == nil || !strings.Contains(err.Error(), "no cipher suite supported by both client and server") {
			t.Errorf("err = %v, want no shared cipher suite", err)
		}
	})
}

// I3: Go client with a Brainpool client certificate; OpenSSL server with a
// Brainpool certificate that requires a client certificate.
func TestI3GoClientOpenSSLServer(t *testing.T) {
	for _, tt := range []struct {
		groups string
		want   tls.CurveID
	}{
		{"P-256:brainpoolP256r1", tls.CurveP256},
		{"brainpoolP256r1", tlsutil.CurveBrainpoolP256r1},
	} {
		t.Run(tt.groups, func(t *testing.T) {
			config := brainpoolClient(t, "bp256-client", "bp256-ca")
			cs, out, err := clientWithSServer(t, config, sServerArgs(tt.groups)...)
			if err != nil {
				t.Fatal(err)
			}
			checkPeer(t, cs, "localhost", tt.want)
			wantOutput(t, out, "CN = ivory Brainpool P256 Client", "Peer signature type: ECDSA", "CIPHER is ECDHE-ECDSA-")
		})
	}

	// A client that also offers TLS 1.3 lists the TLS 1.2 Brainpool groups.
	t.Run("TLS 1.2 and 1.3 offered", func(t *testing.T) {
		config := brainpoolClient(t, "bp256-client", "bp256-ca")
		config.MaxVersion = 0
		config.CurvePreferences = nil
		cs, _, err := clientWithSServer(t, config, sServerArgs("brainpoolP256r1")...)
		if err != nil {
			t.Fatal(err)
		}
		checkPeer(t, cs, "localhost", tlsutil.CurveBrainpoolP256r1)
	})

	// Without KeyExchanges, the client offers no Brainpool group, and
	// OpenSSL refuses the Brainpool certificate: in TLS 1.2 it accepts an
	// ECDSA certificate only on a curve the peer listed in supported_groups.
	t.Run("no KeyExchanges", func(t *testing.T) {
		config := brainpoolClient(t, "bp256-client", "bp256-ca")
		config.KeyExchanges = nil
		config.CurvePreferences = nil
		_, out, err := clientWithSServer(t, config, sServerArgs("P-256:brainpoolP256r1")...)
		if err == nil {
			t.Fatal("handshake succeeded")
		}
		wantOutput(t, out, "no shared cipher")
	})
}

// I4: Go client and Go server, mutual authentication, on all three
// curves.
func TestI4GoGo(t *testing.T) {
	for _, tt := range []struct {
		bits  string
		curve brainpool.Curve
		group tls.CurveID
	}{
		{"256", brainpool.P256r1(), tlsutil.CurveBrainpoolP256r1},
		{"384", brainpool.P384r1(), tlsutil.CurveBrainpoolP384r1},
		{"512", brainpool.P512r1(), tlsutil.CurveBrainpoolP512r1},
	} {
		t.Run("bp"+tt.bits, func(t *testing.T) {
			server := brainpoolServer(t, "bp"+tt.bits+"-server", "bp"+tt.bits+"-ca")
			server.KeyExchanges = tlsutil.KeyExchanges(tt.curve)
			client := brainpoolClient(t, "bp"+tt.bits+"-client", "bp"+tt.bits+"-ca")
			client.KeyExchanges = tlsutil.KeyExchanges(tt.curve)
			client.CurvePreferences = []tls.CurveID{tt.group}
			scs, ccs, err := goGo(t, client, server)
			if err != nil {
				t.Fatal(err)
			}
			checkPeer(t, ccs, "localhost", tt.group)
			checkPeer(t, scs, "ivory Brainpool P"+tt.bits+" Client", tt.group)
		})
	}
}

// goGo runs a handshake between a Go client and a Go server over loopback.
func goGo(t *testing.T, client, server *tls.Config) (serverState, clientState tls.ConnectionState, err error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		cs  tls.ConnectionState
		err error
	}
	results := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			results <- result{err: err}
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(opTimeout))
		c := tls.Server(conn, server)
		err = c.Handshake()
		if err == nil {
			buf := make([]byte, len(greeting))
			_, err = c.Read(buf)
		}
		results <- result{c.ConnectionState(), err}
	}()
	clientState, cerr := goClient(ln.Addr().String(), client)
	r := <-results
	if cerr != nil {
		return r.cs, clientState, cerr
	}
	return r.cs, clientState, r.err
}

// I7: negative cases. Each must fail closed.
func TestI7Negative(t *testing.T) {
	// N1: the server signs with another Brainpool key than the one in its
	// certificate.
	wrongKey := func(t *testing.T) *tls.Config {
		config := brainpoolServer(t, "bp256-server", "bp256-ca")
		cert := config.Certificates[0]
		b, err := os.ReadFile(pkiFile("bp256-wrongkey.key"))
		if err != nil {
			t.Fatal(err)
		}
		wrong, err := tlsutil.ParsePrivateKeyPEM(b)
		if err != nil {
			t.Fatal(err)
		}
		cert.PrivateKey = wrong
		config.Certificates = []tls.Certificate{cert}
		config.ClientAuth = tls.NoClientCert
		return config
	}
	t.Run("N1 wrong server key, Go client", func(t *testing.T) {
		client := brainpoolClient(t, "bp256-client", "bp256-ca")
		_, _, err := goGo(t, client, wrongKey(t))
		if err == nil || !strings.Contains(err.Error(), "invalid signature by the server certificate") {
			t.Errorf("err = %v, want an invalid signature", err)
		}
	})
	t.Run("N1 wrong server key, OpenSSL client", func(t *testing.T) {
		_, out, err := serverWithSClient(t, wrongKey(t), sClientArgs("P-256:brainpoolP256r1")...)
		if err == nil {
			t.Fatal("handshake succeeded")
		}
		wantOutput(t, out, "bad signature")
	})

	// N2: the peer's chain doesn't lead to the trusted root: the client
	// trusts a CA with the same name as the server's CA and another key.
	t.Run("N2 evil CA, Go client", func(t *testing.T) {
		client := brainpoolClient(t, "bp256-client", "bp256-evil-ca")
		_, out, err := clientWithSServer(t, client, sServerArgs("P-256:brainpoolP256r1")...)
		if err == nil || !strings.Contains(err.Error(), "not signed by a trusted root") {
			t.Errorf("err = %v, want an untrusted chain", err)
		}
		wantOutput(t, out, "bad certificate")
	})
	t.Run("N2 evil CA, Go server", func(t *testing.T) {
		server := brainpoolServer(t, "bp256-server", "bp256-evil-ca")
		_, _, err := serverWithSClient(t, server, sClientArgs("P-256:brainpoolP256r1")...)
		if err == nil || !strings.Contains(err.Error(), "not signed by a trusted root") {
			t.Errorf("err = %v, want an untrusted chain", err)
		}
	})

	// N3: without VerifyUnsupportedSignature, Brainpool peers fail.
	t.Run("N3 no hook, Go client", func(t *testing.T) {
		client := brainpoolClient(t, "bp256-client", "bp256-ca")
		client.VerifyUnsupportedSignature = nil
		_, out, err := clientWithSServer(t, client, sServerArgs("P-256:brainpoolP256r1")...)
		if err == nil || !strings.Contains(err.Error(), "unsupported type of public key") {
			t.Errorf("err = %v, want an unsupported key error", err)
		}
		wantOutput(t, out, "unsupported certificate")
	})
	t.Run("N3 no hook, Go server", func(t *testing.T) {
		server := brainpoolServer(t, "bp256-server", "bp256-ca")
		server.VerifyUnsupportedSignature = nil
		_, out, err := serverWithSClient(t, server, sClientArgs("P-256:brainpoolP256r1")...)
		if err == nil || !strings.Contains(err.Error(), "unsupported public key") {
			t.Errorf("err = %v, want an unsupported key error", err)
		}
		wantOutput(t, out, "unsupported certificate")
	})

	// Expired: the OpenSSL server's certificate is not valid in 2037.
	t.Run("expired", func(t *testing.T) {
		client := brainpoolClient(t, "bp256-client", "bp256-ca")
		client.VerifyConnection = (&tlsutil.ChainVerifier{
			Roots:    []*x509.Certificate{readCert(t, "bp256-ca")},
			KeyUsage: x509.ExtKeyUsageServerAuth,
			Time:     func() time.Time { return time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC) },
		}).VerifyConnection
		_, _, err := clientWithSServer(t, client, sServerArgs("P-256:brainpoolP256r1")...)
		if err == nil || !strings.Contains(err.Error(), "not valid at 2037") {
			t.Errorf("err = %v, want an expired certificate", err)
		}
	})
}
