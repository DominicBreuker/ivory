//go:build ivory

package tlsutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"golang.org/x/crypto/cryptobyte"
)

func readChain(t *testing.T, name string) [][]byte {
	t.Helper()
	var chain [][]byte
	rest := readFile(t, name+".pem")
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return chain
		}
		chain = append(chain, block.Bytes)
	}
}

func readKey(t *testing.T, name string) *brainpool.PrivateKey {
	t.Helper()
	k, err := ParsePrivateKeyPEM(readFile(t, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewSigner(t *testing.T) {
	k := readKey(t, "bp256-server")
	s := NewSigner(k)
	if _, ok := s.(interface {
		ECDH(*brainpool.PublicKey) ([]byte, error)
	}); ok {
		t.Error("NewSigner exposes ECDH")
	}
	if !k.PublicKey().Equal(s.Public()) {
		t.Error("Public doesn't match the key")
	}
	digest := sha256.Sum256([]byte("message"))
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !brainpool.VerifyASN1(k.PublicKey(), digest[:], sig) {
		t.Error("signature doesn't verify")
	}
}

// signOnly hides every method of a crypto.Signer but Public and Sign.
type signOnly struct{ crypto.Signer }

func TestCertificate(t *testing.T) {
	for _, tt := range []struct {
		name   string
		scheme tls.SignatureScheme
	}{
		{"bp256-server", ECDSABrainpoolP256r1TLS13SHA256},
		{"bp384-server", ECDSABrainpoolP384r1TLS13SHA384},
		{"bp512-server", ECDSABrainpoolP512r1TLS13SHA512},
	} {
		chain := readChain(t, tt.name)
		k := readKey(t, tt.name)
		raw := RawSigner(k.PublicKey(), func(digest []byte) ([]byte, error) { return brainpool.SignRaw(nil, k, digest) })
		for _, key := range []crypto.Signer{k, NewSigner(k), raw, signOnly{k}} {
			cert, err := Certificate(chain, key)
			if err != nil {
				t.Fatalf("%s, %T: %v", tt.name, key, err)
			}
			if cert.Leaf == nil || cert.Leaf.Subject.CommonName != "localhost" {
				t.Errorf("%s, %T: unexpected certificate %+v", tt.name, key, cert)
			}
			// TLS 1.3 needs a crypto.MessageSigner; ours are kept,
			// other signers are wrapped.
			ms, ok := cert.PrivateKey.(crypto.MessageSigner)
			if !ok {
				t.Errorf("%s, %T: PrivateKey is a %T, not a crypto.MessageSigner", tt.name, key, cert.PrivateKey)
			} else if _, ours := key.(crypto.MessageSigner); ours && ms != key {
				t.Errorf("%s, %T: PrivateKey was replaced by a %T", tt.name, key, ms)
			}
			// The TLS 1.3 scheme of the key's curve only.
			want := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512, tt.scheme}
			if !equalSchemes(cert.SupportedSignatureAlgorithms, want) {
				t.Errorf("%s, %T: SupportedSignatureAlgorithms = %v, want %v", tt.name, key, cert.SupportedSignatureAlgorithms, want)
			}
		}
	}

	chain := readChain(t, "bp256-server")
	k := readKey(t, "bp256-server")
	for _, tt := range []struct {
		name    string
		chain   [][]byte
		key     crypto.Signer
		wantErr string
	}{
		{"empty chain", nil, k, "empty certificate chain"},
		{"wrong key", chain, readKey(t, "bp256-wrongkey"), "does not match"},
		{"key of another curve", chain, readKey(t, "bp384-server"), "does not match"},
		{"P-256 leaf", readChain(t, "p256-ca"), k, "not a Brainpool key"},
		{"garbage", [][]byte{{0x30, 0x00}}, k, "x509"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Certificate(tt.chain, tt.key)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestSignMessage checks the signers that crypto/tls uses in TLS 1.3: they
// hash with the hash of the TLS 1.3 scheme of their curve and refuse
// other schemes.
func TestSignMessage(t *testing.T) {
	msg := []byte("TLS 1.3 signed content")
	for _, tt := range []struct {
		name   string
		scheme tls.SignatureScheme
		other  tls.SignatureScheme
		hash   crypto.Hash
	}{
		{"bp256-server", ECDSABrainpoolP256r1TLS13SHA256, ECDSABrainpoolP384r1TLS13SHA384, crypto.SHA256},
		{"bp384-server", ECDSABrainpoolP384r1TLS13SHA384, ECDSABrainpoolP512r1TLS13SHA512, crypto.SHA384},
		{"bp512-server", ECDSABrainpoolP512r1TLS13SHA512, ECDSABrainpoolP256r1TLS13SHA256, crypto.SHA512},
	} {
		k := readKey(t, tt.name)
		cert, err := Certificate(readChain(t, tt.name), signOnly{k})
		if err != nil {
			t.Fatal(err)
		}
		raw := RawSigner(k.PublicKey(), func(digest []byte) ([]byte, error) { return brainpool.SignRaw(nil, k, digest) })
		for _, s := range []crypto.MessageSigner{NewSigner(k), raw, cert.PrivateKey.(crypto.MessageSigner)} {
			h := tt.hash.New()
			h.Write(msg)
			digest := h.Sum(nil)
			// SignMessage, and Sign with the same options (as
			// crypto.MessageSigner asks), hash the message.
			for _, sign := range []func([]byte, crypto.SignerOpts) ([]byte, error){
				func(m []byte, o crypto.SignerOpts) ([]byte, error) { return s.SignMessage(rand.Reader, m, o) },
				func(m []byte, o crypto.SignerOpts) ([]byte, error) { return s.Sign(rand.Reader, m, o) },
			} {
				sig, err := sign(msg, &tls.SignatureSchemeOptions{Scheme: tt.scheme})
				if err != nil {
					t.Fatalf("%s, %T: %v", tt.name, s, err)
				}
				if !brainpool.VerifyASN1(k.PublicKey(), digest, sig) {
					t.Errorf("%s, %T: signature doesn't verify", tt.name, s)
				}
				for _, opts := range []crypto.SignerOpts{
					&tls.SignatureSchemeOptions{Scheme: tt.other},
					&tls.SignatureSchemeOptions{Scheme: tls.ECDSAWithP256AndSHA256},
				} {
					if _, err := sign(msg, opts); err == nil {
						t.Errorf("%s, %T: signed with %v", tt.name, s, opts)
					}
				}
			}
			if _, err := s.SignMessage(rand.Reader, msg, crypto.Hash(0)); err == nil {
				t.Errorf("%s, %T: SignMessage signed an unhashed message", tt.name, s)
			}
			sig, err := s.SignMessage(rand.Reader, msg, tt.hash)
			if err != nil || !brainpool.VerifyASN1(k.PublicKey(), digest, sig) {
				t.Errorf("%s, %T: SignMessage with %v: %v", tt.name, s, tt.hash, err)
			}
		}
	}
}

func equalSchemes(a, b []tls.SignatureScheme) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRawSigner(t *testing.T) {
	for _, name := range []string{"bp256-server", "bp384-server", "bp512-server"} {
		t.Run(name, func(t *testing.T) {
			k := readKey(t, name)
			var calls int
			s := RawSigner(k.PublicKey(), func(digest []byte) ([]byte, error) {
				calls++
				return brainpool.SignRaw(nil, k, digest)
			})
			if !k.PublicKey().Equal(s.Public()) {
				t.Error("Public doesn't match the key")
			}
			digest := sha512.Sum384([]byte("message"))
			sig, err := s.Sign(nil, digest[:], crypto.SHA384)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Errorf("card called %d times, want 1", calls)
			}
			// VerifyASN1 accepts only DER.
			if !brainpool.VerifyASN1(k.PublicKey(), digest[:], sig) {
				t.Error("signature doesn't verify")
			}
		})
	}

	k := readKey(t, "bp256-server")
	digest := sha256.Sum256([]byte("message"))
	good, err := brainpool.SignRaw(nil, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	errCard := errors.New("card removed")
	for _, tt := range []struct {
		name    string
		sign    func([]byte) ([]byte, error)
		digest  []byte
		wantErr string
	}{
		{"card error", func([]byte) ([]byte, error) { return nil, errCard }, digest[:], "card removed"},
		{"short", func([]byte) ([]byte, error) { return good[:63], nil }, digest[:], "63 bytes"},
		{"DER instead of raw", func(d []byte) ([]byte, error) { return k.Sign(nil, d, crypto.SHA256) }, digest[:], "bytes, want 64"},
		{"bad signature", func([]byte) ([]byte, error) {
			bad := bytes.Clone(good)
			bad[63] ^= 1
			return bad, nil
		}, digest[:], "doesn't verify"},
		{"other digest", func([]byte) ([]byte, error) { return good, nil }, make([]byte, 32), "doesn't verify"},
		{"digest length", func([]byte) ([]byte, error) { return good, nil }, digest[:20], "digest length"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := RawSigner(k.PublicKey(), tt.sign)
			sig, err := s.Sign(nil, tt.digest, crypto.SHA256)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
			if sig != nil {
				t.Errorf("returned a signature with an error")
			}
		})
	}
}

func TestAddASN1Integer(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"01", "020101"},
		{"0001", "020101"},
		{"000000", "020100"},
		{"7f", "02017f"},
		{"80", "02020080"},
		{"0080", "02020080"},
		{"00ff01", "020300ff01"},
		{"123456", "0203123456"},
	} {
		in, _ := hex.DecodeString(tt.in)
		var b cryptobyte.Builder
		addASN1Integer(&b, in)
		if got := hex.EncodeToString(b.BytesOrPanic()); got != tt.want {
			t.Errorf("addASN1Integer(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

// TestHandshakeOpaqueKeys runs TLS 1.2 handshakes between Go peers with
// Brainpool identities on both sides: the server signs through RawSigner,
// the client with a *brainpool.PrivateKey, and each side verifies the
// other with VerifyUnsupportedSignature and ChainVerifier.
func TestHandshakeOpaqueKeys(t *testing.T) {
	now := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	serverKey := readKey(t, "bp256-server")
	var cardCalls int
	serverCert, err := Certificate(readChain(t, "bp256-server"), RawSigner(serverKey.PublicKey(), func(digest []byte) ([]byte, error) {
		cardCalls++
		return brainpool.SignRaw(nil, serverKey, digest)
	}))
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := X509KeyPair(readFile(t, "bp384-client.pem"), readFile(t, "bp384-client.key"))
	if err != nil {
		t.Fatal(err)
	}
	server := &tls.Config{
		Time:                       now,
		MinVersion:                 tls.VersionTLS12,
		MaxVersion:                 tls.VersionTLS12,
		Certificates:               []tls.Certificate{serverCert},
		ClientAuth:                 tls.RequireAnyClientCert,
		VerifyUnsupportedSignature: VerifyUnsupportedSignature,
		VerifyConnection: (&ChainVerifier{Roots: []*x509.Certificate{readCert(t, "bp384-ca")},
			KeyUsage: x509.ExtKeyUsageClientAuth, Time: now}).VerifyConnection,
	}
	client := &tls.Config{
		Time:                       now,
		ServerName:                 "localhost",
		MinVersion:                 tls.VersionTLS12,
		MaxVersion:                 tls.VersionTLS12,
		Certificates:               []tls.Certificate{clientCert},
		InsecureSkipVerify:         true,
		VerifyUnsupportedSignature: VerifyUnsupportedSignature,
		VerifyConnection: (&ChainVerifier{Roots: []*x509.Certificate{readCert(t, "bp256-ca")},
			KeyUsage: x509.ExtKeyUsageServerAuth, Time: now}).VerifyConnection,
		KeyExchanges:     KeyExchanges(brainpool.P256r1()),
		CurvePreferences: []tls.CurveID{CurveBrainpoolP256r1},
	}
	server.KeyExchanges = client.KeyExchanges
	server.CurvePreferences = client.CurvePreferences

	c, s := net.Pipe()
	done := make(chan error, 1)
	var serverState tls.ConnectionState
	go func() {
		srv := tls.Server(s, server)
		err := srv.Handshake()
		serverState = srv.ConnectionState()
		done <- err
	}()
	cli := tls.Client(c, client)
	clientErr := cli.Handshake()
	clientState := cli.ConnectionState()
	if clientErr != nil {
		c.Close() // unblock the server
	}
	serverErr := <-done
	c.Close()
	s.Close()
	if clientErr != nil || serverErr != nil {
		t.Fatalf("client: %v, server: %v", clientErr, serverErr)
	}
	if clientState.CurveID != CurveBrainpoolP256r1 {
		t.Errorf("group = %v, want brainpoolP256r1", clientState.CurveID)
	}
	if clientState.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 &&
		clientState.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 &&
		clientState.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
		t.Errorf("cipher suite = %v, want an ECDHE_ECDSA suite", tls.CipherSuiteName(clientState.CipherSuite))
	}
	if cardCalls != 1 {
		t.Errorf("card signed %d times, want 1", cardCalls)
	}
	if len(serverState.PeerCertificates) == 0 || serverState.PeerCertificates[0].Subject.CommonName != "ivory Brainpool P384 Client" {
		t.Errorf("server saw client certificates %v", serverState.PeerCertificates)
	}
}

func TestSupportsCertificate(t *testing.T) {
	bp, err := X509KeyPair(readFile(t, "bp256-server.pem"), readFile(t, "bp256-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	rsaCert, err := tls.LoadX509KeyPair(pki+"/rsa-server.pem", pki+"/rsa-server.key")
	if err != nil {
		t.Fatal(err)
	}
	chi := func(curves ...tls.CurveID) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   curves,
			SupportedPoints:   []uint8{0},
			SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256, tls.PKCS1WithSHA256},
			SupportedVersions: []uint16{tls.VersionTLS12},
		}
	}
	if err := SupportsCertificate(chi(tls.CurveP256, CurveBrainpoolP256r1), &bp); err != nil {
		t.Errorf("with brainpoolP256r1 offered: %v", err)
	}
	if err := SupportsCertificate(chi(tls.CurveP256, CurveBrainpoolP384r1), &bp); err == nil {
		t.Error("accepted a brainpoolP256r1 certificate without the group")
	}
	if err := SupportsCertificate(chi(tls.CurveP256), &rsaCert); err != nil {
		t.Errorf("RSA certificate: %v", err)
	}
	get := GetCertificate([]tls.Certificate{bp, rsaCert})
	if c, _ := get(chi(tls.CurveP256, CurveBrainpoolP256r1)); c != &bp && c.Leaf != bp.Leaf {
		t.Error("with brainpoolP256r1 offered: did not pick the Brainpool certificate")
	}
	if c, _ := get(chi(tls.X25519, tls.CurveP256)); c.PrivateKey != rsaCert.PrivateKey {
		t.Error("without brainpoolP256r1: did not pick the RSA certificate")
	}
}
