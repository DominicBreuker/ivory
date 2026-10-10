//go:build ivory

package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
)

var allCurves = []brainpool.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1()}

// handshake runs a handshake between client and server over a pipe and
// returns the client's state and both errors.
func handshake(client, server *tls.Config) (tls.ConnectionState, error, error) {
	c, s := net.Pipe()
	done := make(chan error, 1)
	go func() {
		srv := tls.Server(s, server)
		err := srv.Handshake()
		if err != nil {
			s.Close() // unblock the client
		}
		done <- err
	}()
	cli := tls.Client(c, client)
	clientErr := cli.Handshake()
	if clientErr != nil {
		c.Close() // unblock the server
	}
	serverErr := <-done
	c.Close()
	s.Close()
	return cli.ConnectionState(), clientErr, serverErr
}

// fallbackClient returns a client that offers TLS 1.2 and 1.3. legacy
// makes it behave like Windows SChannel: X25519, P-256, P-384 and the
// Brainpool groups 26-28 only, and no TLS 1.3 Brainpool signature scheme.
// Otherwise it is an RFC 8734 client.
func fallbackClient(t *testing.T, legacy bool, now func() time.Time) *tls.Config {
	c := &tls.Config{
		Time:                       now,
		ServerName:                 "localhost",
		MinVersion:                 tls.VersionTLS12,
		MaxVersion:                 tls.VersionTLS13,
		InsecureSkipVerify:         true,
		VerifyUnsupportedSignature: VerifyUnsupportedSignature,
		VerifyConnection: (&ChainVerifier{Roots: []*x509.Certificate{readCert(t, "bp256-ca"), readCert(t, "rsa-ca")},
			KeyUsage: x509.ExtKeyUsageServerAuth, Time: now}).VerifyConnection,
		KeyExchanges:     KeyExchanges(allCurves...),
		SignatureSchemes: SignatureSchemes(),
	}
	if legacy {
		c.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384,
			CurveBrainpoolP256r1, CurveBrainpoolP384r1, CurveBrainpoolP512r1}
		c.SignatureSchemes = []tls.SignatureScheme{tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512,
			tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512}
	}
	return c
}

// fallbackServer returns a server for TLS 1.2 and 1.3 with the identities
// certs, chosen by GetCertificate, and TLS12Fallback if fallback is set.
func fallbackServer(certs []tls.Certificate, fallback bool, now func() time.Time) *tls.Config {
	c := &tls.Config{
		Time:                       now,
		MinVersion:                 tls.VersionTLS12,
		MaxVersion:                 tls.VersionTLS13,
		GetCertificate:             GetCertificate(certs),
		KeyExchanges:               KeyExchanges(allCurves...),
		SignatureSchemes:           SignatureSchemes(),
		VerifyUnsupportedSignature: VerifyUnsupportedSignature,
	}
	if fallback {
		c.GetConfigForClient = TLS12Fallback(c, certs)
	}
	return c
}

func TestTLS12Fallback(t *testing.T) {
	now := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	bp, err := X509KeyPair(readFile(t, "bp256-server.pem"), readFile(t, "bp256-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	rsaCert, err := tls.LoadX509KeyPair(pki+"/rsa-server.pem", pki+"/rsa-server.key")
	if err != nil {
		t.Fatal(err)
	}
	onlyTLS13 := func(c *tls.Config) *tls.Config { c.MinVersion = tls.VersionTLS13; return c }
	noBrainpool := func(c *tls.Config) *tls.Config {
		c.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
		return c
	}
	for _, tt := range []struct {
		name     string
		client   *tls.Config
		certs    []tls.Certificate
		fallback bool
		ok       bool
		version  uint16
		// brainpool: the server used its Brainpool identity (the key
		// exchange may use any group; crypto/tls prefers X25519).
		brainpool bool
	}{
		// Without the fallback, an SChannel-like client can't use the
		// Brainpool identity in TLS 1.3, and crypto/tls doesn't fall back.
		{"legacy client, no fallback", fallbackClient(t, true, now), []tls.Certificate{bp}, false, false, 0, false},
		// With it, TLS 1.2 with the Brainpool identity; the Go client
		// checks the downgrade sentinel, so success means there was none.
		{"legacy client", fallbackClient(t, true, now), []tls.Certificate{bp}, true, true, tls.VersionTLS12, true},
		// RFC 8734 clients keep TLS 1.3.
		{"RFC 8734 client", fallbackClient(t, false, now), []tls.Certificate{bp}, true, true, tls.VersionTLS13, true},
		// A legacy client that can use another identity in TLS 1.3 keeps
		// TLS 1.3.
		{"legacy client, RSA identity too", fallbackClient(t, true, now), []tls.Certificate{bp, rsaCert}, true, true, tls.VersionTLS13, false},
		// No fallback where TLS 1.2 isn't offered or doesn't help.
		{"legacy client, TLS 1.3 only", onlyTLS13(fallbackClient(t, true, now)), []tls.Certificate{bp}, true, false, 0, false},
		{"client without Brainpool groups", noBrainpool(fallbackClient(t, true, now)), []tls.Certificate{bp}, true, false, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cs, clientErr, serverErr := handshake(tt.client, fallbackServer(tt.certs, tt.fallback, now))
			if !tt.ok {
				if clientErr == nil && serverErr == nil {
					t.Fatalf("handshake succeeded with %s, want failure", tls.VersionName(cs.Version))
				}
				return
			}
			if clientErr != nil || serverErr != nil {
				t.Fatalf("client: %v, server: %v", clientErr, serverErr)
			}
			if cs.Version != tt.version {
				t.Errorf("%s, want %s", tls.VersionName(cs.Version), tls.VersionName(tt.version))
			}
			// crypto/tls leaves PublicKey nil for keys it doesn't know.
			if got := cs.PeerCertificates[0].PublicKey == nil; got != tt.brainpool {
				t.Errorf("Brainpool identity used: %v, want %v", got, tt.brainpool)
			}
		})
	}
}

func TestTLS12FallbackConditions(t *testing.T) {
	bp, err := X509KeyPair(readFile(t, "bp256-server.pem"), readFile(t, "bp256-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	legacyHello := func() *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []tls.CurveID{CurveBrainpoolP256r1, tls.X25519, tls.CurveP256},
			SupportedPoints:   []uint8{0},
			SignatureSchemes:  []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256},
			SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		}
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{bp}}
	if !needsTLS12Fallback(config, nil, legacyHello()) {
		t.Error("legacy ClientHello: no fallback")
	}
	for _, tt := range []struct {
		name   string
		config *tls.Config
		hello  func(*tls.ClientHelloInfo)
	}{
		{"server TLS 1.3 only", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{bp}}, nil},
		{"server TLS 1.2 only", &tls.Config{MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{bp}}, nil},
		{"no certificates", &tls.Config{}, nil},
		{"client TLS 1.3 only", config, func(chi *tls.ClientHelloInfo) { chi.SupportedVersions = []uint16{tls.VersionTLS13} }},
		{"client without TLS 1.2 Brainpool group", config, func(chi *tls.ClientHelloInfo) {
			chi.SupportedCurves = []tls.CurveID{CurveBrainpoolP256r1TLS13, tls.X25519}
		}},
		{"client with a TLS 1.3 Brainpool scheme", config, func(chi *tls.ClientHelloInfo) {
			chi.SignatureSchemes = append(chi.SignatureSchemes, ECDSABrainpoolP384r1TLS13SHA384)
		}},
		{"certificate unusable in TLS 1.2", config, func(chi *tls.ClientHelloInfo) {
			chi.SupportedCurves = []tls.CurveID{CurveBrainpoolP384r1, tls.X25519}
		}},
	} {
		chi := legacyHello()
		if tt.hello != nil {
			tt.hello(chi)
		}
		if needsTLS12Fallback(tt.config, nil, chi) {
			t.Errorf("%s: fallback", tt.name)
		}
	}
}
