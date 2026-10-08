//go:build ivory

package tlsutil

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
)

// TLS named groups (RFC 7027 for TLS 1.2, RFC 8734 for TLS 1.3) and
// TLS 1.3 signature schemes (RFC 8734) for the Brainpool curves.
const (
	CurveBrainpoolP256r1      tls.CurveID = 26 // TLS 1.2 only
	CurveBrainpoolP384r1      tls.CurveID = 27
	CurveBrainpoolP512r1      tls.CurveID = 28
	CurveBrainpoolP256r1TLS13 tls.CurveID = 31 // TLS 1.3 only
	CurveBrainpoolP384r1TLS13 tls.CurveID = 32
	CurveBrainpoolP512r1TLS13 tls.CurveID = 33

	ECDSABrainpoolP256r1TLS13SHA256 tls.SignatureScheme = 0x081A
	ECDSABrainpoolP384r1TLS13SHA384 tls.SignatureScheme = 0x081B
	ECDSABrainpoolP512r1TLS13SHA512 tls.SignatureScheme = 0x081C
)

// curveIDs returns the TLS 1.2 and TLS 1.3 group IDs of c.
func curveIDs(c brainpool.Curve) (tls12, tls13 tls.CurveID) {
	switch c {
	case brainpool.P256r1():
		return CurveBrainpoolP256r1, CurveBrainpoolP256r1TLS13
	case brainpool.P384r1():
		return CurveBrainpoolP384r1, CurveBrainpoolP384r1TLS13
	case brainpool.P512r1():
		return CurveBrainpoolP512r1, CurveBrainpoolP512r1TLS13
	}
	panic("tlsutil: unknown curve")
}

// KeyExchanges returns tls.KeyExchange entries for the curves: for each
// curve, its TLS 1.2 group (26–28) with MaxVersion TLS 1.2 and its TLS 1.3
// group (31–33) with MinVersion TLS 1.3. Every handshake uses a fresh
// ephemeral key from crypto/rand (GS-A_5322).
func KeyExchanges(curves ...brainpool.Curve) []tls.KeyExchange {
	var kes []tls.KeyExchange
	for _, c := range curves {
		tls12, tls13 := curveIDs(c)
		generate := func() (crypto.Decapsulator, error) {
			k, err := brainpool.GenerateKey(c)
			if err != nil {
				return nil, err
			}
			return k, nil
		}
		parse := func(b []byte) (crypto.Encapsulator, error) {
			pub, err := brainpool.NewPublicKey(c, b)
			if err != nil {
				return nil, err
			}
			return pub, nil
		}
		kes = append(kes,
			tls.KeyExchange{ID: tls12, MaxVersion: tls.VersionTLS12, GenerateKey: generate, NewEncapsulator: parse},
			tls.KeyExchange{ID: tls13, MinVersion: tls.VersionTLS13, GenerateKey: generate, NewEncapsulator: parse})
	}
	return kes
}

// VerifyUnsupportedSignature is a tls.Config.VerifyUnsupportedSignature
// for Brainpool ECDSA keys. It accepts the TLS 1.2 schemes 0x0403, 0x0503
// and 0x0603 (SHA-256, SHA-384, SHA-512) on any Brainpool curve, and the
// TLS 1.3 schemes 0x081A, 0x081B and 0x081C only on their curve. Every
// other scheme and key is an error. Signatures must be strict DER.
func VerifyUnsupportedSignature(leaf *x509.Certificate, scheme tls.SignatureScheme, signed, sig []byte) error {
	k, err := x509util.ParsePKIXPublicKey(leaf.RawSubjectPublicKeyInfo)
	if err != nil {
		return fmt.Errorf("tlsutil: peer key: %w", err)
	}
	pub, ok := k.(*brainpool.PublicKey)
	if !ok {
		return fmt.Errorf("tlsutil: peer key is a %T, not a Brainpool key", k)
	}
	var h crypto.Hash
	switch scheme {
	case tls.ECDSAWithP256AndSHA256:
		h = crypto.SHA256
	case tls.ECDSAWithP384AndSHA384:
		h = crypto.SHA384
	case tls.ECDSAWithP521AndSHA512:
		h = crypto.SHA512
	default:
		var curve brainpool.Curve
		if h, curve = tls13Scheme(scheme); h == 0 {
			return fmt.Errorf("tlsutil: signature scheme %v is not allowed for Brainpool keys", scheme)
		}
		if pub.Curve() != curve {
			return fmt.Errorf("tlsutil: signature scheme %v needs %v, peer key is on %v", scheme, curve, pub.Curve())
		}
	}
	hh := h.New()
	hh.Write(signed)
	if !brainpool.VerifyASN1(pub, hh.Sum(nil), sig) {
		return errors.New("tlsutil: ECDSA verification failure")
	}
	return nil
}

// tls13Scheme returns the hash and the curve of a TLS 1.3 Brainpool
// signature scheme (RFC 8734), or zero and nil for other schemes.
func tls13Scheme(s tls.SignatureScheme) (crypto.Hash, brainpool.Curve) {
	switch s {
	case ECDSABrainpoolP256r1TLS13SHA256:
		return crypto.SHA256, brainpool.P256r1()
	case ECDSABrainpoolP384r1TLS13SHA384:
		return crypto.SHA384, brainpool.P384r1()
	case ECDSABrainpoolP512r1TLS13SHA512:
		return crypto.SHA512, brainpool.P512r1()
	}
	return 0, nil
}

// tls13SchemeForCurve returns the TLS 1.3 signature scheme of c.
func tls13SchemeForCurve(c brainpool.Curve) tls.SignatureScheme {
	switch c {
	case brainpool.P256r1():
		return ECDSABrainpoolP256r1TLS13SHA256
	case brainpool.P384r1():
		return ECDSABrainpoolP384r1TLS13SHA384
	case brainpool.P512r1():
		return ECDSABrainpoolP512r1TLS13SHA512
	}
	panic("tlsutil: unknown curve")
}

// tls12ECDSASchemes are the signature schemes a Brainpool key can sign
// with in TLS 1.2, where ECDSA schemes are not bound to a curve.
var tls12ECDSASchemes = []tls.SignatureScheme{
	tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
}

// SignatureSchemes returns a list for tls.Config.SignatureSchemes: the
// signature schemes of BSI TR-02102-2 (2026-01), Table 11, that crypto/tls
// or this package can verify, in the order of that table. They are RSA-PSS
// with rsaEncryption keys (0x0804–0x0806), ECDSA on the NIST curves
// (0x0403, 0x0503, 0x0603) and ECDSA on the Brainpool curves in TLS 1.3
// (0x081A–0x081C); Ed25519, ML-DSA, PKCS #1 v1.5, SHA-1 and RSA-PSS with
// RSASSA-PSS keys are left out. crypto/tls advertises the Brainpool schemes
// only for TLS 1.3, and only with Config.VerifyUnsupportedSignature set.
//
// A TLS 1.3 peer needs them to present a Brainpool certificate. In
// TLS 1.2, Brainpool keys sign with 0x0403, 0x0503 and 0x0603.
func SignatureSchemes() []tls.SignatureScheme {
	return []tls.SignatureScheme{
		tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512,
		tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
		ECDSABrainpoolP256r1TLS13SHA256, ECDSABrainpoolP384r1TLS13SHA384, ECDSABrainpoolP512r1TLS13SHA512,
	}
}

// X509KeyPair is like tls.X509KeyPair for a Brainpool key in PKCS #8 or
// SEC 1 form. The certificate chain may also hold certificates with other
// keys. It returns Certificate(chain, NewSigner(key)): Leaf is set,
// PrivateKey signs in TLS 1.2 and TLS 1.3, and SupportedSignatureAlgorithms
// lists the TLS 1.2 ECDSA schemes and the TLS 1.3 scheme of the key's
// curve. For a key on a smart card, use Certificate with RawSigner
// instead.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (tls.Certificate, error) {
	var cert tls.Certificate
	for {
		var block *pem.Block
		block, certPEMBlock = pem.Decode(certPEMBlock)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("tlsutil: no certificate in PEM data")
	}
	key, err := ParsePrivateKeyPEM(keyPEMBlock)
	if err != nil {
		return tls.Certificate{}, err
	}
	return Certificate(cert.Certificate, NewSigner(key))
}

// LoadX509KeyPair is like tls.LoadX509KeyPair for a Brainpool key; see
// X509KeyPair.
func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return X509KeyPair(certPEM, keyPEM)
}

// ParsePrivateKeyPEM parses the first "PRIVATE KEY" (PKCS #8) or "EC
// PRIVATE KEY" (SEC 1) block in pemBytes, which must hold a Brainpool key.
func ParsePrivateKeyPEM(pemBytes []byte) (*brainpool.PrivateKey, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("tlsutil: no private key in PEM data")
		}
		switch block.Type {
		case "PRIVATE KEY":
			k, err := x509util.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			bk, ok := k.(*brainpool.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("tlsutil: private key is a %T, not a Brainpool key", k)
			}
			return bk, nil
		case "EC PRIVATE KEY":
			return x509util.ParseECPrivateKey(block.Bytes)
		}
	}
}
