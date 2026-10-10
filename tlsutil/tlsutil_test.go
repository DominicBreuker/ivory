//go:build ivory

package tlsutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
)

const pki = "../testdata/pki"

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pki, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(readFile(t, name+".pem"))
	if block == nil {
		t.Fatalf("%s: no PEM data", name)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

func TestKeyExchanges(t *testing.T) {
	kes := KeyExchanges(brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1())
	want := []struct {
		id       tls.CurveID
		min, max uint16
	}{
		{26, 0, tls.VersionTLS12}, {31, tls.VersionTLS13, 0},
		{27, 0, tls.VersionTLS12}, {32, tls.VersionTLS13, 0},
		{28, 0, tls.VersionTLS12}, {33, tls.VersionTLS13, 0},
	}
	if len(kes) != len(want) {
		t.Fatalf("got %d entries, want %d", len(kes), len(want))
	}
	for i, w := range want {
		ke := kes[i]
		if ke.ID != w.id || ke.MinVersion != w.min || ke.MaxVersion != w.max {
			t.Errorf("entry %d = %v [%x, %x], want %v [%x, %x]", i, ke.ID, ke.MinVersion, ke.MaxVersion, w.id, w.min, w.max)
		}
		dk, err := ke.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		ek, err := ke.NewEncapsulator(dk.Encapsulator().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		shared, ct := ek.Encapsulate()
		got, err := dk.Decapsulate(ct)
		if err != nil || string(got) != string(shared) {
			t.Errorf("entry %d: Decapsulate = %x, %v; want %x", i, got, err, shared)
		}
	}
}

func TestVerifyUnsupportedSignature(t *testing.T) {
	leaf256 := readCert(t, "bp256-server")
	leaf384 := readCert(t, "bp384-server")
	key256, err := ParsePrivateKeyPEM(readFile(t, "bp256-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	key384, err := ParsePrivateKeyPEM(readFile(t, "bp384-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	signed := []byte("handshake transcript")
	sign := func(k *brainpool.PrivateKey, h crypto.Hash) []byte {
		hh := h.New()
		hh.Write(signed)
		sig, err := k.Sign(rand.Reader, hh.Sum(nil), h)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	for _, tt := range []struct {
		name   string
		leaf   *x509.Certificate
		scheme tls.SignatureScheme
		sig    []byte
		ok     bool
	}{
		{"TLS 1.2 SHA-256", leaf256, tls.ECDSAWithP256AndSHA256, sign(key256, crypto.SHA256), true},
		{"TLS 1.2 SHA-384 on P256r1", leaf256, tls.ECDSAWithP384AndSHA384, sign(key256, crypto.SHA384), true},
		{"TLS 1.2 SHA-512 on P384r1", leaf384, tls.ECDSAWithP521AndSHA512, sign(key384, crypto.SHA512), true},
		{"TLS 1.3 P256r1", leaf256, ECDSABrainpoolP256r1TLS13SHA256, sign(key256, crypto.SHA256), true},
		{"TLS 1.3 P384r1", leaf384, ECDSABrainpoolP384r1TLS13SHA384, sign(key384, crypto.SHA384), true},
		{"TLS 1.3 scheme of another curve", leaf256, ECDSABrainpoolP384r1TLS13SHA384, sign(key256, crypto.SHA384), false},
		{"SHA-1", leaf256, tls.ECDSAWithSHA1, sign(key256, crypto.SHA1), false},
		{"RSA scheme", leaf256, tls.PKCS1WithSHA256, sign(key256, crypto.SHA256), false},
		{"hash mismatch", leaf256, tls.ECDSAWithP256AndSHA256, sign(key256, crypto.SHA384), false},
		{"other key", leaf384, tls.ECDSAWithP256AndSHA256, sign(key256, crypto.SHA256), false},
		{"P-256 leaf", readCert(t, "p256-ca"), tls.ECDSAWithP256AndSHA256, sign(key256, crypto.SHA256), false},
		{"trailing data", leaf256, tls.ECDSAWithP256AndSHA256, append(sign(key256, crypto.SHA256), 0), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyUnsupportedSignature(tt.leaf, tt.scheme, signed, tt.sig)
			if tt.ok != (err == nil) {
				t.Errorf("err = %v, want ok = %v", err, tt.ok)
			}
		})
	}
}

func TestX509KeyPair(t *testing.T) {
	cert, err := X509KeyPair(readFile(t, "bp256-server.pem"), readFile(t, "bp256-server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != "localhost" || len(cert.Certificate) != 1 {
		t.Errorf("unexpected certificate %+v", cert.Leaf)
	}
	if _, ok := cert.PrivateKey.(crypto.MessageSigner); !ok {
		t.Errorf("PrivateKey is a %T, not a crypto.MessageSigner", cert.PrivateKey)
	}
	want := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512, ECDSABrainpoolP256r1TLS13SHA256}
	if !equalSchemes(cert.SupportedSignatureAlgorithms, want) {
		t.Errorf("SupportedSignatureAlgorithms = %v, want %v", cert.SupportedSignatureAlgorithms, want)
	}
	if _, err := X509KeyPair(readFile(t, "bp256-server.pem"), readFile(t, "bp256-server.sec1.pem")); err != nil {
		t.Errorf("SEC 1 key: %v", err)
	}
	if _, err := X509KeyPair(readFile(t, "bp256-server.pem"), readFile(t, "bp256-wrongkey.key")); err == nil {
		t.Error("accepted a key that doesn't match the certificate")
	}
	if _, err := X509KeyPair(readFile(t, "p256-ca.pem"), readFile(t, "p256-ca.key")); err == nil {
		t.Error("accepted a P-256 key")
	}
}

func TestChainVerifier(t *testing.T) {
	cert := func(names ...string) []*x509.Certificate {
		var cs []*x509.Certificate
		for _, n := range names {
			cs = append(cs, readCert(t, n))
		}
		return cs
	}
	in2030 := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	in2037 := func() time.Time { return time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC) }
	for _, tt := range []struct {
		name    string
		v       ChainVerifier
		chain   []*x509.Certificate
		dnsName string
		wantErr string // "" for success
	}{
		{"bp256 server", ChainVerifier{Roots: cert("bp256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-server"), "localhost", ""},
		{"bp512 client", ChainVerifier{Roots: cert("bp512-ca"), KeyUsage: x509.ExtKeyUsageClientAuth}, cert("bp512-client"), "", ""},
		{"chain with root", ChainVerifier{Roots: cert("bp256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-server", "bp256-ca"), "", ""},
		{"Brainpool leaf, P-256 CA", ChainVerifier{Roots: cert("p256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-under-p256"), "localhost", ""},
		{"P-256 leaf, Brainpool CA", ChainVerifier{Roots: cert("bp256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("p256-under-bp256"), "localhost", ""},
		{"several roots", ChainVerifier{Roots: cert("rsa-ca", "bp384-ca", "bp256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth, Time: in2030}, cert("bp256-server"), "", ""},
		{"evil CA", ChainVerifier{Roots: cert("bp256-evil-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-server"), "", "not signed by a trusted root"},
		{"evil CA in the chain", ChainVerifier{Roots: cert("bp256-evil-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-server", "bp256-evil-ca"), "", "bad signature"},
		{"extra certificate", ChainVerifier{Roots: cert("bp256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-server", "bp256-evil-ca"), "", ""},
		{"other CA", ChainVerifier{Roots: cert("bp384-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-server"), "", "not signed by a trusted root"},
		{"expired", ChainVerifier{Roots: cert("bp256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth, Time: in2037}, cert("bp256-server"), "", "not valid at 2037"},
		{"key usage", ChainVerifier{Roots: cert("bp256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-client"), "", "extended key usage"},
		{"host name", ChainVerifier{Roots: cert("bp256-ca"), KeyUsage: x509.ExtKeyUsageServerAuth}, cert("bp256-server"), "example.com", "not example.com"},
		{"no certificate", ChainVerifier{Roots: cert("bp256-ca")}, nil, "", "no peer certificate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.v.Verify(tt.chain, tt.dnsName)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestChainVerifierConstraints checks basic constraints, path lengths and
// critical extensions, with a P-256 PKI made on the fly.
func TestChainVerifierConstraints(t *testing.T) {
	serial := int64(0)
	type node struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}
	issue := func(cn string, parent *node, mod func(*x509.Certificate)) *node {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		if mod != nil {
			mod(tmpl)
		}
		issuer, signer := tmpl, key
		if parent != nil {
			issuer, signer = parent.cert, parent.key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return &node{c, key}
	}
	ee := func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	critical := func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}, Critical: true, Value: []byte{0x30, 0x00}}}
	}
	pathLen0 := func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 0, true }

	root := issue("root", nil, nil)
	inter := issue("intermediate", root, nil)
	leaf := issue("leaf", inter, ee)
	// An end entity that signs a certificate as if it were a CA.
	notCA := issue("not a CA", root, ee)
	forged := issue("forged", notCA, ee)
	noBC := issue("no basic constraints", root, func(c *x509.Certificate) { c.BasicConstraintsValid, c.IsCA = false, false })
	underNoBC := issue("leaf", noBC, ee)
	inter0 := issue("intermediate, path length 0", root, pathLen0)
	inter2 := issue("second intermediate", inter0, nil)
	leaf2 := issue("leaf", inter2, ee)
	leaf0 := issue("leaf", inter0, ee)
	root0 := issue("root, path length 0", nil, pathLen0)
	interUnder0 := issue("intermediate", root0, nil)
	leafUnder0 := issue("leaf", interUnder0, ee)
	criticalLeaf := issue("leaf", inter, func(c *x509.Certificate) { ee(c); critical(c) })
	criticalInter := issue("intermediate", root, critical)
	underCritical := issue("leaf", criticalInter, ee)

	chain := func(nodes ...*node) []*x509.Certificate {
		var cs []*x509.Certificate
		for _, n := range nodes {
			cs = append(cs, n.cert)
		}
		return cs
	}
	for _, tt := range []struct {
		name    string
		roots   []*x509.Certificate
		chain   []*x509.Certificate
		wantErr string
	}{
		{"leaf, intermediate", chain(root), chain(leaf, inter), ""},
		{"end entity as issuer", chain(root), chain(forged, notCA), "cannot sign"},
		{"issuer without basic constraints", chain(root), chain(underNoBC, noBC), "cannot sign"},
		{"intermediate path length 0, one intermediate below", chain(root), chain(leaf2, inter2, inter0), "path length"},
		{"intermediate path length 0, leaf below", chain(root), chain(leaf0, inter0), ""},
		{"root path length 0, one intermediate below", chain(root0), chain(leafUnder0, interUnder0), "path length"},
		{"critical extension in the leaf", chain(root), chain(criticalLeaf, inter), "unhandled critical extension"},
		{"critical extension in an intermediate", chain(root), chain(underCritical, criticalInter), "unhandled critical extension"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := &ChainVerifier{Roots: tt.roots, KeyUsage: x509.ExtKeyUsageServerAuth}
			err := v.Verify(tt.chain, "")
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
