//go:build ivory

package ti

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/tlsutil"
)

// testPKI is a small TI-like PKI: a Brainpool component CA, a P-256 CA, a
// CA with the Brainpool CA's name and another key, a CRL signer, and end
// entities.
type testPKI struct {
	bpCA, p256CA, evilCA, crlSigner          *x509.Certificate
	bpCAKey, p256CAKey, evilCAKey, signerKey crypto.Signer
}

func newTestPKI(t testing.TB) *testPKI {
	p := &testPKI{
		bpCAKey:   newBrainpool(t, brainpool.P256r1()),
		p256CAKey: newP256(t),
		evilCAKey: newBrainpool(t, brainpool.P256r1()),
		signerKey: newBrainpool(t, brainpool.P256r1()),
	}
	p.bpCA = issue(t, caTemplate("TI Komp-CA (Brainpool)"), p.bpCAKey, nil, p.bpCAKey)
	p.p256CA = issue(t, caTemplate("TI Komp-CA (P-256)"), p.p256CAKey, nil, p.p256CAKey)
	p.evilCA = issue(t, caTemplate("TI Komp-CA (Brainpool)"), p.evilCAKey, nil, p.evilCAKey)
	signerTmpl := caTemplate("TI CRL signer")
	signerTmpl.IsCA = false
	signerTmpl.KeyUsage = x509.KeyUsageCRLSign
	p.crlSigner = issue(t, signerTmpl, p.signerKey, p.bpCA, p.bpCAKey)
	return p
}

// identity issues an end-entity certificate for key under ca and returns it
// as a tls.Certificate.
func identity(t testing.TB, tmpl *x509.Certificate, key crypto.Signer, ca *x509.Certificate, caKey crypto.Signer) tls.Certificate {
	t.Helper()
	leaf := issue(t, tmpl, key, ca, caKey)
	if bk, ok := key.(*brainpool.PrivateKey); ok {
		c, err := tlsutil.Certificate([][]byte{leaf.Raw}, bk)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}

func TestVerifier(t *testing.T) {
	p := newTestPKI(t)
	key := newBrainpool(t, brainpool.P256r1())
	leaf := func(mod func(*x509.Certificate)) *x509.Certificate {
		tmpl := eeTemplate("konnektor.example", x509.ExtKeyUsageClientAuth, PolicySAKAUT)
		if mod != nil {
			mod(tmpl)
		}
		return issue(t, tmpl, key, p.bpCA, p.bpCAKey)
	}
	good := leaf(nil)
	underP256 := issue(t, eeTemplate("konnektor.example", x509.ExtKeyUsageClientAuth, PolicySAKAUT), key, p.p256CA, p.p256CAKey)
	p256Leaf := issue(t, eeTemplate("konnektor.example", x509.ExtKeyUsageClientAuth, PolicySAKAUT), newP256(t), p.bpCA, p.bpCAKey)
	byEvil := issue(t, eeTemplate("konnektor.example", x509.ExtKeyUsageClientAuth, PolicySAKAUT), key, p.evilCA, p.evilCAKey)

	base := func() *Verifier {
		v := KonnektorVerifier([]*x509.Certificate{p.bpCA, p.p256CA})
		v.Time = testTime
		return v
	}
	withCRLs := func(crls ...CRL) *Verifier {
		v := base()
		v.CRLs = crls
		return v
	}
	current := func(revoked ...*big.Int) *x509.RevocationList {
		return makeCRL(t, p.bpCA, p.bpCAKey, testNow.Add(-time.Hour), testNow.Add(time.Hour), revoked...)
	}
	for _, tt := range []struct {
		name    string
		v       *Verifier
		leaf    *x509.Certificate
		dnsName string
		wantErr string
	}{
		{"Brainpool leaf, Brainpool CA", base(), good, "", ""},
		{"Brainpool leaf, P-256 CA", base(), underP256, "", ""},
		{"P-256 leaf, Brainpool CA", base(), p256Leaf, "", ""},
		{"host name", base(), good, "konnektor.example", ""},
		{"wrong host name", base(), good, "other.example", "not other.example"},
		{"evil CA with the same name", base(), byEvil, "", "bad signature"},
		{"unknown CA", KonnektorVerifier([]*x509.Certificate{p.p256CA}), good, "", "not issued by a trusted CA"},
		{"intermediate not trusted", KonnektorVerifier([]*x509.Certificate{p.p256CA}), p.crlSigner, "", "not issued by a trusted CA"},
		{"wrong policy", base(), leaf(func(c *x509.Certificate) { c.Policies = []x509.OID{PolicySMKTAUT} }), "", "none of the policies"},
		{"no policy", base(), leaf(func(c *x509.Certificate) { c.Policies = nil }), "", "none of the policies"},
		{"wrong extended key usage", base(), leaf(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }), "", "extended key usage"},
		{"wrong key usage", base(), leaf(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }), "", "key usage"},
		{"CA as leaf", base(), leaf(func(c *x509.Certificate) { c.IsCA = true }), "", "CA certificate"},
		{"expired", base(), leaf(func(c *x509.Certificate) { c.NotBefore, c.NotAfter = testStart, testStart.Add(time.Hour) }), "", "not valid at"},
		{"not yet valid", base(), leaf(func(c *x509.Certificate) { c.NotBefore, c.NotAfter = testNow.Add(time.Hour), testEnd }), "", "not valid at"},
		{"no certificate", base(), nil, "", "no peer certificate"},
		{"CRL by the CA, not revoked", withCRLs(CRL{List: current(big.NewInt(1)), CA: p.bpCA}), good, "", ""},
		{"CRL by the CA, revoked", withCRLs(CRL{List: current(good.SerialNumber), CA: p.bpCA}), good, "", "revoked"},
		{"CRL by a CRL signer, revoked", withCRLs(CRL{List: makeCRL(t, p.crlSigner, p.signerKey, testNow.Add(-time.Hour), testNow.Add(time.Hour), good.SerialNumber), CA: p.bpCA, Signer: p.crlSigner}), good, "", "revoked"},
		{"CRL by a CRL signer, not revoked", withCRLs(CRL{List: makeCRL(t, p.crlSigner, p.signerKey, testNow.Add(-time.Hour), testNow.Add(time.Hour)), CA: p.bpCA, Signer: p.crlSigner}), good, "", ""},
		{"CRL for another CA", withCRLs(CRL{List: makeCRL(t, p.p256CA, p.p256CAKey, testNow.Add(-time.Hour), testNow.Add(time.Hour), good.SerialNumber), CA: p.p256CA}), good, "", ""},
		{"CRL with a bad signature", withCRLs(CRL{List: makeCRL(t, p.bpCA, p.evilCAKey, testNow.Add(-time.Hour), testNow.Add(time.Hour)), CA: p.bpCA}), good, "", "bad signature"},
		{"CRL from the wrong issuer", withCRLs(CRL{List: makeCRL(t, p.crlSigner, p.signerKey, testNow.Add(-time.Hour), testNow.Add(time.Hour)), CA: p.bpCA}), good, "", "not issued by its signer"},
		{"CRL expired", withCRLs(CRL{List: makeCRL(t, p.bpCA, p.bpCAKey, testNow.Add(-2*time.Hour), testNow.Add(-time.Hour)), CA: p.bpCA}), good, "", "not current"},
		{"CRL required, none", func() *Verifier { v := base(); v.RequireCRL = true; return v }(), good, "", "no CRL"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.v.Time == nil {
				tt.v.Time = testTime
			}
			err := tt.v.Verify(tt.leaf, tt.dnsName)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

type result struct {
	client, server       tls.ConnectionState
	clientErr, serverErr error
}

// handshake runs one TLS handshake over a pipe.
func handshake(t testing.TB, client, server *tls.Config) result {
	t.Helper()
	c, s := net.Pipe()
	done := make(chan result, 1)
	go func() {
		srv := tls.Server(s, server)
		err := srv.Handshake()
		done <- result{server: srv.ConnectionState(), serverErr: err}
	}()
	cli := tls.Client(c, client)
	err := cli.Handshake()
	if err != nil {
		c.Close() // unblock the server
	}
	r := <-done
	c.Close()
	s.Close()
	r.client, r.clientErr = cli.ConnectionState(), err
	return r
}

// ktSetup is an eHealth-KT with a Brainpool and an RSA identity, and the
// Konnektor's identity.
type ktSetup struct {
	pki            *testPKI
	ecc, rsa       tls.Certificate
	konnektor      tls.Certificate
	konnektorSPKI  []byte
	ktVerifier     *Verifier
	konnektorCheck *Verifier
}

func newKT(t testing.TB) *ktSetup {
	p := newTestPKI(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := &ktSetup{
		pki: p,
		ecc: identity(t, eeTemplate("kt.example", x509.ExtKeyUsageServerAuth, PolicySMKTAUT), newBrainpool(t, brainpool.P256r1()), p.bpCA, p.bpCAKey),
		rsa: identity(t, eeTemplate("kt.example", x509.ExtKeyUsageServerAuth, PolicySMKTAUT), rsaKey, p.p256CA, p.p256CAKey),
		konnektor: identity(t, eeTemplate("konnektor.example", x509.ExtKeyUsageClientAuth, PolicySAKAUT),
			newBrainpool(t, brainpool.P256r1()), p.bpCA, p.bpCAKey),
		ktVerifier: &Verifier{CAs: []*x509.Certificate{p.bpCA, p.p256CA}, Policies: []x509.OID{PolicySMKTAUT}, Time: testTime},
	}
	k.konnektorSPKI = k.konnektor.Leaf.RawSubjectPublicKeyInfo
	k.konnektorCheck = KonnektorVerifier([]*x509.Certificate{p.bpCA})
	k.konnektorCheck.Time = testTime
	return k
}

func (k *ktSetup) server(t testing.TB, paired bool, states *[]State) *tls.Config {
	t.Helper()
	s := &KTServer{
		ECC:       &k.ecc,
		RSA:       &k.rsa,
		Konnektor: k.konnektorCheck,
		Paired: func(spki []byte) bool {
			return paired && string(spki) == string(k.konnektorSPKI)
		},
		OnState: func(state State, cs tls.ConnectionState, reason error) {
			*states = append(*states, state)
		},
	}
	c, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	c.Time = testTime
	return c
}

func TestKTServer(t *testing.T) {
	k := newKT(t)
	other := newTestPKI(t)
	strangerKey := newBrainpool(t, brainpool.P256r1())
	stranger := identity(t, eeTemplate("konnektor.example", x509.ExtKeyUsageClientAuth, PolicySAKAUT), strangerKey, other.bpCA, other.bpCAKey)

	for _, tt := range []struct {
		name      string
		paired    bool
		cert      *tls.Certificate
		suites    []uint16
		wantState State
		wantRSA   bool
	}{
		{"paired Konnektor", true, &k.konnektor, nil, StateClientWithPairing, false},
		{"unpaired Konnektor", false, &k.konnektor, nil, StateClientWithoutPairing, false},
		{"no client certificate (A_22890)", true, nil, nil, StateInvalidClient, false},
		{"client certificate from another PKI", true, &stranger, nil, StateInvalidClient, false},
		{"ECDSA suites only: ECC identity (A_22453)", true, &k.konnektor, SuitesECDSA, StateClientWithPairing, false},
		// With the profile kt (P6), the server asks only for RSA client
		// certificates on RSA suites, so the Konnektor sends none.
		{"RSA suites only: RSA identity (A_22453)", true, &k.konnektor, SuitesRSA, map[bool]State{false: StateClientWithPairing, true: StateInvalidClient}[ktProfile], true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var states []State
			server := k.server(t, tt.paired, &states)
			var client *tls.Config
			if tt.cert != nil {
				client = ConnectorClientConfig(*tt.cert, k.ktVerifier)
			} else {
				client = ClientConfig(nil, k.ktVerifier)
			}
			client.Time = testTime
			if tt.suites != nil {
				client.CipherSuites = tt.suites
			}
			r := handshake(t, client, server)
			if r.clientErr != nil || r.serverErr != nil {
				t.Fatalf("client: %v, server: %v", r.clientErr, r.serverErr)
			}
			if len(states) != 1 || states[0] != tt.wantState {
				t.Errorf("states = %v, want [%v]", states, tt.wantState)
			}
			_, isRSA := r.client.PeerCertificates[0].PublicKey.(*rsa.PublicKey)
			if isRSA != tt.wantRSA {
				t.Errorf("server used the RSA identity: %v, want %v", isRSA, tt.wantRSA)
			}
			if r.server.Version != tls.VersionTLS12 {
				t.Errorf("version = %x, want TLS 1.2", r.server.Version)
			}
		})
	}

	// The Brainpool groups: the Konnektor's preset offers them, and a
	// server that prefers them picks one.
	t.Run("brainpoolP256r1 group", func(t *testing.T) {
		var states []State
		server := k.server(t, true, &states)
		server.CurvePreferences = []tls.CurveID{tlsutil.CurveBrainpoolP256r1}
		client := ConnectorClientConfig(k.konnektor, k.ktVerifier)
		client.Time = testTime
		r := handshake(t, client, server)
		if r.clientErr != nil || r.serverErr != nil {
			t.Fatalf("client: %v, server: %v", r.clientErr, r.serverErr)
		}
		if r.client.CurveID != tlsutil.CurveBrainpoolP256r1 {
			t.Errorf("group = %v, want brainpoolP256r1", r.client.CurveID)
		}
	})

	// A client that doesn't offer brainpoolP256r1 can't use the Brainpool
	// identity in TLS 1.2 (RFC 8422, Section 5.1): it gets the RSA one.
	t.Run("no Brainpool groups: RSA identity", func(t *testing.T) {
		var states []State
		server := k.server(t, true, &states)
		client := ClientConfig(nil, k.ktVerifier)
		client.Time = testTime
		client.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384}
		r := handshake(t, client, server)
		if r.clientErr != nil || r.serverErr != nil {
			t.Fatalf("client: %v, server: %v", r.clientErr, r.serverErr)
		}
		if _, ok := r.client.PeerCertificates[0].PublicKey.(*rsa.PublicKey); !ok {
			t.Error("server did not use the RSA identity")
		}
	})

	if _, err := (&KTServer{Konnektor: k.konnektorCheck}).Config(); err == nil {
		t.Error("KTServer without identities accepted")
	}
}

func TestServerClientConfig(t *testing.T) {
	p := newTestPKI(t)
	serverCert := identity(t, eeTemplate("fd.example", x509.ExtKeyUsageServerAuth, PolicyFDTLSS), newBrainpool(t, brainpool.P384r1()), p.bpCA, p.bpCAKey)
	clientCert := identity(t, eeTemplate("client.example", x509.ExtKeyUsageClientAuth, PolicyFDTLSC), newBrainpool(t, brainpool.P256r1()), p.bpCA, p.bpCAKey)
	serverCheck := &Verifier{CAs: []*x509.Certificate{p.bpCA}, ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, Policies: []x509.OID{PolicyFDTLSS}, Time: testTime}
	clientCheck := &Verifier{CAs: []*x509.Certificate{p.bpCA}, ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Policies: []x509.OID{PolicyFDTLSC}, Time: testTime}

	for _, tt := range []struct {
		name       string
		serverName string
		clientCert *tls.Certificate
		wantErr    string
	}{
		{"mutual", "fd.example", &clientCert, ""},
		{"wrong host name", "other.example", &clientCert, "not other.example"},
		{"no client certificate", "fd.example", nil, "didn't provide a certificate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := ServerConfig([]tls.Certificate{serverCert}, clientCheck)
			server.Time = testTime
			client := ClientConfig(tt.clientCert, serverCheck)
			client.Time = testTime
			client.ServerName = tt.serverName
			r := handshake(t, client, server)
			if tt.wantErr == "" {
				if r.clientErr != nil || r.serverErr != nil {
					t.Fatalf("client: %v, server: %v", r.clientErr, r.serverErr)
				}
				return
			}
			err := r.clientErr
			if r.serverErr != nil && strings.Contains(r.serverErr.Error(), tt.wantErr) {
				err = r.serverErr
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("client: %v, server: %v; want %q", r.clientErr, r.serverErr, tt.wantErr)
			}
		})
	}

	t.Run("brainpoolP512r1", func(t *testing.T) {
		server := ServerConfig([]tls.Certificate{serverCert}, nil)
		server.Time = testTime
		AddBrainpoolP512r1(server)
		server.CurvePreferences = []tls.CurveID{tlsutil.CurveBrainpoolP512r1}
		client := ClientConfig(nil, serverCheck)
		client.Time = testTime
		AddBrainpoolP512r1(client)
		r := handshake(t, client, server)
		if r.clientErr != nil || r.serverErr != nil {
			t.Fatalf("client: %v, server: %v", r.clientErr, r.serverErr)
		}
		if r.client.CurveID != tlsutil.CurveBrainpoolP512r1 {
			t.Errorf("group = %v, want brainpoolP512r1", r.client.CurveID)
		}
	})
}

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestSessionResumption(t *testing.T) {
	p := newTestPKI(t)
	serverCert := identity(t, eeTemplate("fd.example", x509.ExtKeyUsageServerAuth, PolicyFDTLSS), newBrainpool(t, brainpool.P256r1()), p.bpCA, p.bpCAKey)

	setup := func(limitServer, limitClient bool) (*clock, *tls.Config, *tls.Config, *SessionTickets) {
		clk := &clock{testNow}
		check := &Verifier{CAs: []*x509.Certificate{p.bpCA}, Time: clk.now}
		server := ServerConfig([]tls.Certificate{serverCert}, nil)
		server.Time = clk.now
		tickets := &SessionTickets{Time: clk.now}
		if limitServer {
			if err := tickets.Enable(server); err != nil {
				t.Fatal(err)
			}
		} else {
			server.SessionTicketsDisabled = false // Go's own limit: 7 days
		}
		client := ClientConfig(nil, check)
		client.Time = clk.now
		client.ServerName = "fd.example"
		if limitClient {
			client.ClientSessionCache = NewClientSessionCache(8, clk.now)
		} else {
			client.ClientSessionCache = tls.NewLRUClientSessionCache(8)
		}
		return clk, client, server, tickets
	}
	resumes := func(t *testing.T, client, server *tls.Config) bool {
		t.Helper()
		r := handshake(t, client, server)
		if r.clientErr != nil || r.serverErr != nil {
			t.Fatalf("client: %v, server: %v", r.clientErr, r.serverErr)
		}
		return r.client.DidResume
	}

	t.Run("server", func(t *testing.T) {
		clk, client, server, _ := setup(true, false)
		if resumes(t, client, server) {
			t.Fatal("first handshake resumed")
		}
		clk.t = clk.t.Add(23 * time.Hour)
		if !resumes(t, client, server) {
			t.Error("no resumption after 23 h")
		}
		// The server re-issued a ticket for the same secret; the 24 h
		// count from the full handshake.
		clk.t = clk.t.Add(2 * time.Hour)
		if resumes(t, client, server) {
			t.Error("resumed 25 h after the full handshake")
		}
	})

	t.Run("client", func(t *testing.T) {
		clk, client, server, _ := setup(false, true)
		if resumes(t, client, server) {
			t.Fatal("first handshake resumed")
		}
		clk.t = clk.t.Add(23 * time.Hour)
		if !resumes(t, client, server) {
			t.Error("no resumption after 23 h")
		}
		clk.t = clk.t.Add(2 * time.Hour)
		if resumes(t, client, server) {
			t.Error("resumed 25 h after the full handshake")
		}
	})

	t.Run("ticket key rotation", func(t *testing.T) {
		clk, client, server, tickets := setup(true, false)
		if resumes(t, client, server) {
			t.Fatal("first handshake resumed")
		}
		clk.t = clk.t.Add(time.Hour)
		if err := tickets.Rotate(server); err != nil {
			t.Fatal(err)
		}
		if !resumes(t, client, server) {
			t.Error("no resumption with the previous ticket key")
		}
		// The resumption brought a ticket under the new key; two more
		// rotations drop that key.
		for range 2 {
			if err := tickets.Rotate(server); err != nil {
				t.Fatal(err)
			}
		}
		if resumes(t, client, server) {
			t.Error("resumed with a ticket key older than the previous one")
		}
	})

	t.Run("off by default", func(t *testing.T) {
		clk := &clock{testNow}
		server := ServerConfig([]tls.Certificate{serverCert}, nil)
		server.Time = clk.now
		client := ClientConfig(nil, &Verifier{CAs: []*x509.Certificate{p.bpCA}, Time: clk.now})
		client.Time = clk.now
		client.ClientSessionCache = tls.NewLRUClientSessionCache(8)
		resumes(t, client, server)
		if resumes(t, client, server) {
			t.Error("the preset resumed a session without SessionTickets.Enable")
		}
	})
}
