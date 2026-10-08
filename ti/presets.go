//go:build ivory

package ti

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/tlsutil"
)

// TI cipher suites for TLS 1.2: the ECDSA suites of A_17124-03 and
// A_17089-03, the RSA suites of GS-A_4384-03. With the overlay profile kt,
// a client offers ECDSA suites first whatever the order (A_17124-03 item 3,
// A_17094-02); without it, Go interleaves them.
var (
	SuitesECDSA = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	SuitesRSA   = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
)

// Curves are the TI groups (GS-A_4384-03, A_17094-02): P-256 and P-384
// (MUSS), brainpoolP256r1 and brainpoolP384r1 (SOLL, MUSS for the
// Konnektor). AddBrainpoolP512r1 adds brainpoolP512r1 where a role allows
// it (ePA KANN, E-Rezept SOLL).
var Curves = []tls.CurveID{tls.CurveP256, tls.CurveP384, tlsutil.CurveBrainpoolP256r1, tlsutil.CurveBrainpoolP384r1}

// base returns the settings every preset shares.
func base() *tls.Config {
	return &tls.Config{
		MinVersion:                 tls.VersionTLS12,
		MaxVersion:                 tls.VersionTLS12,
		CipherSuites:               slices.Concat(SuitesECDSA, SuitesRSA),
		CurvePreferences:           slices.Clone(Curves),
		KeyExchanges:               tlsutil.KeyExchanges(brainpool.P256r1(), brainpool.P384r1()),
		VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
	}
}

// serverBase is base for servers: no session tickets unless
// SessionTickets.Enable turns them on (GS-A_5322). Clients don't resume
// unless they get a ClientSessionCache, such as NewClientSessionCache.
func serverBase() *tls.Config {
	c := base()
	c.SessionTicketsDisabled = true
	return c
}

// AddBrainpoolP512r1 adds brainpoolP512r1 (group 28) to config's groups.
func AddBrainpoolP512r1(config *tls.Config) {
	if !slices.Contains(config.CurvePreferences, tlsutil.CurveBrainpoolP512r1) {
		config.CurvePreferences = append(config.CurvePreferences, tlsutil.CurveBrainpoolP512r1)
	}
	config.KeyExchanges = append(config.KeyExchanges, tlsutil.KeyExchanges(brainpool.P512r1())...)
}

// ServerConfig returns a TI TLS server configuration with the identities
// certs (for example from tlsutil.X509KeyPair or tlsutil.Certificate),
// chosen by tlsutil.GetCertificate, which also checks the client's groups
// for Brainpool identities; Certificates stays empty. If
// clients is not nil, the server requires a client certificate and checks
// it with clients; the handshake fails if the check fails.
func ServerConfig(certs []tls.Certificate, clients *Verifier) *tls.Config {
	c := serverBase()
	// crypto/tls calls GetCertificate only if Certificates is empty (or
	// the client sent SNI).
	c.GetCertificate = tlsutil.GetCertificate(certs)
	if clients != nil {
		c.ClientAuth = tls.RequireAnyClientCert
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			return clients.Verify(peerLeaf(cs), "")
		}
	}
	return c
}

// ClientConfig returns a TI TLS client configuration that checks the
// server's certificate with server, and its host name against
// Config.ServerName if that is set. cert, if not nil, is the client's
// identity.
func ClientConfig(cert *tls.Certificate, server *Verifier) *tls.Config {
	c := base()
	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}
	// crypto/x509 can't verify Brainpool chains; server checks the
	// certificate in VerifyConnection instead (the VerifyConnection
	// example of crypto/tls).
	c.InsecureSkipVerify = true
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		return server.Verify(peerLeaf(cs), cs.ServerName)
	}
	return c
}

// ConnectorClientConfig returns the configuration of a Konnektor-like TLS
// client towards an eHealth-KT (A_17094-02): ECDSA suites before RSA suites
// (with the overlay profile kt), the groups P-256, P-384, brainpoolP256r1
// and brainpoolP384r1, the client identity cert (C.SAK.AUT), and kt to
// check the terminal's certificate (C.SMKT.AUT). The terminal is reached
// by address, so no host name is checked.
func ConnectorClientConfig(cert tls.Certificate, kt *Verifier) *tls.Config {
	c := ClientConfig(&cert, kt)
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		return kt.Verify(peerLeaf(cs), "")
	}
	return c
}

// KonnektorVerifier returns a Verifier for the Konnektor certificate that
// an eHealth-KT accepts on the SICCT channel: issued by one of cas (the CA
// certificates stored in the terminal that may issue Konnektor
// certificates, A_22888, A_22889), keyUsage digitalSignature, extended key
// usage clientAuth, policy C.SAK.AUT.
func KonnektorVerifier(cas []*x509.Certificate) *Verifier {
	return &Verifier{
		CAs:          cas,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies:     []x509.OID{PolicySAKAUT},
	}
}

// State is the state of the SICCT TLS channel of an eHealth-KT after the
// handshake (A_22456, gemSpec_KT V3.17.1).
type State int

const (
	StateNoSicctTls State = iota
	StateInvalidClient
	StateClientWithoutPairing
	StateClientWithPairing
)

func (s State) String() string {
	switch s {
	case StateNoSicctTls:
		return "State_NoSicctTls"
	case StateInvalidClient:
		return "State_InvalidClient"
	case StateClientWithoutPairing:
		return "State_ClientWithoutPairing"
	case StateClientWithPairing:
		return "State_ClientWithPairing"
	}
	return "State(?)"
}

// A KTServer configures the TLS server of an eHealth-KT on the SICCT
// channel.
type KTServer struct {
	// RSA and ECC are the terminal's identities from the gSMC-KT; at least
	// one must be set (A_17089-03). A client gets ECC if it offers an
	// ECDSA suite and the curve of the ECC key as a group, RSA otherwise
	// (A_22453).
	RSA, ECC *tls.Certificate

	// Konnektor checks the client certificate, usually a
	// KonnektorVerifier.
	Konnektor *Verifier

	// Paired reports whether the public key of the Konnektor's
	// certificate, its DER SubjectPublicKeyInfo, is in a pairing block. If
	// nil, no key is paired.
	Paired func(spki []byte) bool

	// OnState, if not nil, receives the channel state after each
	// handshake, with the reason for StateInvalidClient.
	OnState func(state State, cs tls.ConnectionState, reason error)
}

// Config returns the server configuration. It requests a client
// certificate (RequestClientCert, A_22455) and completes the handshake
// when the client sends none or one that fails the Konnektor check
// (A_22890); the result is StateInvalidClient, not a failed handshake.
// A client certificate must still be proven by a valid signature.
func (s *KTServer) Config() (*tls.Config, error) {
	if s.RSA == nil && s.ECC == nil {
		return nil, errors.New("ti: KTServer has no identity")
	}
	if s.Konnektor == nil {
		return nil, errors.New("ti: KTServer has no Konnektor verifier")
	}
	c := serverBase()
	c.CipherSuites = nil
	if s.ECC != nil {
		c.Certificates = append(c.Certificates, *s.ECC)
		c.CipherSuites = append(c.CipherSuites, SuitesECDSA...)
	}
	if s.RSA != nil {
		c.Certificates = append(c.Certificates, *s.RSA)
		c.CipherSuites = append(c.CipherSuites, SuitesRSA...)
	}
	// A client gets the Brainpool identity only if it supports
	// brainpoolP256r1 (or the identity's curve) as a group.
	c.GetCertificate = tlsutil.GetCertificate(c.Certificates)
	c.Certificates = nil // see ServerConfig
	c.ClientAuth = tls.RequestClientCert
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		state, reason := s.state(cs)
		if s.OnState != nil {
			s.OnState(state, cs, reason)
		}
		return nil
	}
	return c, nil
}

func (s *KTServer) state(cs tls.ConnectionState) (State, error) {
	leaf := peerLeaf(cs)
	if leaf == nil {
		return StateInvalidClient, errors.New("ti: no client certificate")
	}
	if err := s.Konnektor.Verify(leaf, ""); err != nil {
		return StateInvalidClient, err
	}
	if s.Paired != nil && s.Paired(leaf.RawSubjectPublicKeyInfo) {
		return StateClientWithPairing, nil
	}
	return StateClientWithoutPairing, nil
}

func peerLeaf(cs tls.ConnectionState) *x509.Certificate {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0]
}
