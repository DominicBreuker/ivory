//go:build ivory

package tlsutil

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// NewSigner returns k as a crypto.MessageSigner and nothing else, for
// tls.Certificate.PrivateKey: its Public method returns k's
// *brainpool.PublicKey, Sign is k.Sign, and SignMessage hashes the message
// and calls Sign. Code that inspects the private key, such as crypto/tls
// checking for other interfaces, sees only a signer.
//
// crypto/tls signs with such keys only with the overlay's opaque-key
// patch, and only with the schemes in
// tls.Certificate.SupportedSignatureAlgorithms; Certificate sets them. In
// TLS 1.3 it calls SignMessage with a *tls.SignatureSchemeOptions for
// the scheme of k's curve (RFC 8734); SignMessage and Sign then hash with
// that scheme's hash, and refuse a scheme for another curve.
func NewSigner(k *brainpool.PrivateKey) crypto.MessageSigner {
	return signer{k}
}

type signer struct {
	k *brainpool.PrivateKey
}

func (s signer) Public() crypto.PublicKey { return s.k.Public() }

func (s signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*tls.SignatureSchemeOptions); ok {
		return signMessage(s.k, s.k.PublicKey(), rand, digest, opts)
	}
	return s.k.Sign(rand, digest, opts)
}

func (s signer) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signMessage(s.k, s.k.PublicKey(), rand, msg, opts)
}

// signMessage hashes msg and signs the digest with s, whose public key is
// pub. The hash is that of opts, or, for a *tls.SignatureSchemeOptions,
// that of a TLS 1.3 Brainpool scheme for pub's curve.
func signMessage(s crypto.Signer, pub *brainpool.PublicKey, rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	h := opts.HashFunc()
	if o, ok := opts.(*tls.SignatureSchemeOptions); ok {
		var curve brainpool.Curve
		h, curve = tls13Scheme(o.Scheme)
		if h == 0 || curve != pub.Curve() {
			return nil, fmt.Errorf("tlsutil: can't sign with signature scheme %v and a %v key", o.Scheme, pub.Curve())
		}
	}
	if h == 0 {
		return nil, errors.New("tlsutil: ECDSA signs a hash; opts names no hash function")
	}
	hh := h.New()
	hh.Write(msg)
	return s.Sign(rand, hh.Sum(nil), h)
}

// messageSigner adds SignMessage to a Brainpool crypto.Signer, for TLS 1.3.
type messageSigner struct {
	crypto.Signer
	pub *brainpool.PublicKey
}

func (s messageSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*tls.SignatureSchemeOptions); ok {
		return signMessage(s.Signer, s.pub, rand, digest, opts)
	}
	return s.Signer.Sign(rand, digest, opts)
}

func (s messageSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signMessage(s.Signer, s.pub, rand, msg, opts)
}

// Certificate returns a tls.Certificate for chain, the DER certificates
// starting with the leaf, and key, a signer for the leaf's Brainpool key
// (from NewSigner or RawSigner, a *brainpool.PrivateKey, or another
// crypto.Signer). It checks that key.Public() matches the leaf, and sets
// Leaf and SupportedSignatureAlgorithms: the TLS 1.2 ECDSA schemes 0x0403,
// 0x0503 and 0x0603, which are not bound to a curve in TLS 1.2, and the
// TLS 1.3 scheme of the key's curve (0x081A, 0x081B or 0x081C, RFC 8734).
//
// crypto/tls needs a crypto.MessageSigner for TLS 1.3. A
// *brainpool.PrivateKey is wrapped with NewSigner, and another signer
// that isn't a crypto.MessageSigner gets a SignMessage method that hashes
// the message as the scheme requires and calls its Sign method.
func Certificate(chain [][]byte, key crypto.Signer) (tls.Certificate, error) {
	if len(chain) == 0 {
		return tls.Certificate{}, errors.New("tlsutil: empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	pub, err := x509util.PublicKey(leaf)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsutil: certificate key: %w", err)
	}
	bp, ok := pub.(*brainpool.PublicKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("tlsutil: certificate key is a %T, not a Brainpool key", pub)
	}
	if k, ok := key.Public().(*brainpool.PublicKey); !ok || !k.Equal(pub) {
		return tls.Certificate{}, errors.New("tlsutil: private key does not match public key")
	}
	switch k := key.(type) {
	case *brainpool.PrivateKey:
		key = NewSigner(k)
	case crypto.MessageSigner:
	default:
		key = messageSigner{key, bp}
	}
	return tls.Certificate{
		Certificate:                  chain,
		PrivateKey:                   key,
		Leaf:                         leaf,
		SupportedSignatureAlgorithms: append(slices.Clone(tls12ECDSASchemes), tls13SchemeForCurve(bp.Curve())),
	}, nil
}

// RawSigner returns a crypto.Signer for pub whose signatures come from
// sign, which returns the plain encoding r || s of an ECDSA signature of
// digest, each a big-endian integer of brainpool.Size bytes. This is the
// output of a smart card's ELC signature (PSO COMPUTE DIGITAL SIGNATURE
// with the ECDSA algorithm, gemSpec_COS), and of brainpool.SignRaw.
// RawSigner encodes it as ASN.1 DER, as crypto.Signer and TLS expect.
//
// sign receives the digest that crypto/tls computed with the hash of the
// negotiated scheme, or, in TLS 1.3, that SignMessage computed with the
// hash of the scheme of pub's curve. RawSigner checks every signature
// against pub before it returns it, so that a faulty card can't make it
// send a bad or leaking signature (about two scalar multiplications per
// signature).
func RawSigner(pub *brainpool.PublicKey, sign func(digest []byte) (rs []byte, err error)) crypto.MessageSigner {
	return &rawSigner{pub, sign}
}

type rawSigner struct {
	pub  *brainpool.PublicKey
	sign func(digest []byte) ([]byte, error)
}

func (s *rawSigner) Public() crypto.PublicKey { return s.pub }

func (s *rawSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signMessage(s, s.pub, rand, msg, opts)
}

func (s *rawSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*tls.SignatureSchemeOptions); ok {
		return signMessage(s, s.pub, rand, digest, opts)
	}
	if opts != nil && opts.HashFunc() != 0 && len(digest) != opts.HashFunc().Size() {
		return nil, errors.New("tlsutil: digest length doesn't match the hash function")
	}
	rs, err := s.sign(digest)
	if err != nil {
		return nil, err
	}
	size := brainpool.Size(s.pub.Curve())
	if len(rs) != 2*size {
		return nil, fmt.Errorf("tlsutil: raw signature has %d bytes, want %d", len(rs), 2*size)
	}
	if !brainpool.VerifyRaw(s.pub, digest, rs) {
		return nil, errors.New("tlsutil: raw signature doesn't verify")
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1Integer(b, rs[:size])
		addASN1Integer(b, rs[size:])
	})
	return b.Bytes()
}

// addASN1Integer adds the non-negative big-endian integer v as a DER
// INTEGER. r and s are public, so this needs no constant time.
func addASN1Integer(b *cryptobyte.Builder, v []byte) {
	for len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	b.AddASN1(asn1.INTEGER, func(b *cryptobyte.Builder) {
		if v[0]&0x80 != 0 {
			b.AddUint8(0)
		}
		b.AddBytes(v)
	})
}
