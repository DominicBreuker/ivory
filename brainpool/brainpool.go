// Package brainpool implements the elliptic curves brainpoolP256r1,
// brainpoolP384r1 and brainpoolP512r1 of RFC 5639: key generation, ECDSA
// and ECDH, in constant time.
//
// The API follows crypto/ecdh and crypto/ecdsa. A *PrivateKey is a
// crypto.Signer that produces ASN.1 DER ECDSA signatures and a
// crypto.Decapsulator for ephemeral ECDH; a *PublicKey is a
// crypto.Encapsulator.
//
// Field and scalar arithmetic use filippo.io/bigmod, the constant-time
// modular arithmetic of the Go standard library. Points use projective
// coordinates with complete addition formulas, and scalar multiplication
// is a Montgomery ladder over a fixed number of bits, so the time of an
// operation does not depend on secret values. Signature nonces follow RFC
// 6979, hedged with fresh randomness (RFC 6979, Section 3.6).
//
// Only uncompressed points are supported.
package brainpool

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"filippo.io/bigmod"
)

// A Curve is one of the Brainpool curves. Its implementations live in this
// package; compare curves with ==.
type Curve interface {
	// String returns the curve's name from RFC 5639, for example
	// "brainpoolP256r1".
	String() string

	params() *curve
}

func (c *curve) String() string { return c.name }
func (c *curve) params() *curve { return c }

var (
	p256r1 = newCurve(&p256r1Params, crypto.SHA256)
	p384r1 = newCurve(&p384r1Params, crypto.SHA384)
	p512r1 = newCurve(&p512r1Params, crypto.SHA512)
)

// P256r1 returns brainpoolP256r1.
func P256r1() Curve { return p256r1 }

// P384r1 returns brainpoolP384r1.
func P384r1() Curve { return p384r1 }

// P512r1 returns brainpoolP512r1.
func P512r1() Curve { return p512r1 }

// Size returns the length in bytes of c's field elements and scalars: 32,
// 48 or 64.
func Size(c Curve) int { return c.params().size }

// A PublicKey is a point on a Brainpool curve other than the point at
// infinity.
type PublicKey struct {
	c *curve
	q *point
	b []byte // uncompressed encoding
}

// A PrivateKey is a scalar d with 1 ≤ d < n and its public key d·G.
type PrivateKey struct {
	c   *curve
	d   []byte      // fixed length, big-endian
	dn  *bigmod.Nat // d mod n
	pub *PublicKey
}

// GenerateKey returns a new private key on c. d is uniformly distributed
// in [1, n−1] (rejection sampling); the randomness comes from crypto/rand.
func GenerateKey(c Curve) (*PrivateKey, error) {
	cp := c.params()
	b := make([]byte, cp.size)
	for {
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		// The Brainpool orders are exactly 8·size bits long, so no
		// masking is needed before the range check.
		if k, err := NewPrivateKey(c, b); err == nil {
			return k, nil
		}
	}
}

// NewPrivateKey returns the private key with scalar d, a big-endian byte
// string of exactly Size(c) bytes with 1 ≤ d < n.
func NewPrivateKey(c Curve, d []byte) (*PrivateKey, error) {
	cp := c.params()
	if len(d) != cp.size {
		return nil, errors.New("brainpool: invalid private key length")
	}
	dn, err := bigmod.NewNat().SetBytes(d, cp.n)
	if err != nil || dn.IsZero() == 1 {
		return nil, errors.New("brainpool: invalid private key")
	}
	x, y, ok := cp.affine(cp.scalarMult(cp.g, d))
	if ok != 1 {
		panic("brainpool: internal error: d·G is the point at infinity")
	}
	pub, err := newPublicKey(cp, x, y)
	if err != nil {
		panic("brainpool: internal error: d·G is not on the curve")
	}
	return &PrivateKey{c: cp, d: append([]byte(nil), d...), dn: dn, pub: pub}, nil
}

// NewPublicKey decodes an uncompressed point, 0x04 || X || Y, on c. X and
// Y must be less than p and satisfy the curve equation. Compressed and
// hybrid encodings and the point at infinity are rejected.
func NewPublicKey(c Curve, uncompressed []byte) (*PublicKey, error) {
	cp := c.params()
	if len(uncompressed) != 1+2*cp.size || uncompressed[0] != 4 {
		return nil, errors.New("brainpool: invalid point encoding")
	}
	return newPublicKey(cp, uncompressed[1:1+cp.size], uncompressed[1+cp.size:])
}

func newPublicKey(c *curve, x, y []byte) (*PublicKey, error) {
	q, err := c.pointFromAffine(x, y)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 1+2*c.size)
	b = append(b, 4)
	b = append(b, x...)
	b = append(b, y...)
	return &PublicKey{c: c, q: q, b: b}, nil
}

// Curve returns the key's curve.
func (k *PublicKey) Curve() Curve { return k.c }

// Bytes returns the uncompressed encoding of k, 0x04 || X || Y.
func (k *PublicKey) Bytes() []byte { return append([]byte(nil), k.b...) }

// Equal reports whether x is a *PublicKey with the same curve and point.
func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	return ok && k.c == xx.c && subtle.ConstantTimeCompare(k.b, xx.b) == 1
}

// Curve returns the key's curve.
func (k *PrivateKey) Curve() Curve { return k.c }

// Bytes returns the scalar d as a big-endian byte string of Size(c) bytes.
func (k *PrivateKey) Bytes() []byte { return append([]byte(nil), k.d...) }

// Equal reports whether x is a *PrivateKey with the same curve and scalar,
// in constant time with respect to the scalars.
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	return ok && k.c == xx.c && subtle.ConstantTimeCompare(k.d, xx.d) == 1
}

// PublicKey returns the public key d·G.
func (k *PrivateKey) PublicKey() *PublicKey { return k.pub }

// Public returns the public key, a *PublicKey, for crypto.Signer.
func (k *PrivateKey) Public() crypto.PublicKey { return k.pub }

// ECDH returns the x-coordinate of d·Q for the peer's public key Q, as a
// big-endian byte string of Size(c) bytes (RFC 8422, Section 5.10; BSI
// TR-03111, Section 4.3.1). peer must be on the same curve.
func (k *PrivateKey) ECDH(peer *PublicKey) ([]byte, error) {
	if peer == nil || peer.c != k.c {
		return nil, errors.New("brainpool: public key on another curve")
	}
	x, _, ok := k.c.affine(k.c.scalarMult(peer.q, k.d))
	if ok != 1 {
		// Impossible for a valid peer key: the group has prime order n
		// and 1 ≤ d < n.
		return nil, errors.New("brainpool: ECDH result is the point at infinity")
	}
	return x, nil
}

// Encapsulator returns the public key, for crypto.Decapsulator. Its
// encapsulation key is the uncompressed point.
func (k *PrivateKey) Encapsulator() crypto.Encapsulator { return k.pub }

// Decapsulate treats ciphertext as the peer's uncompressed public point and
// returns the ECDH shared secret, for crypto.Decapsulator. With
// PublicKey.Encapsulate and a fresh key per exchange this is ephemeral
// ECDH as used in TLS (RFC 8422, RFC 8446).
func (k *PrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	peer, err := NewPublicKey(k.c, ciphertext)
	if err != nil {
		return nil, err
	}
	return k.ECDH(peer)
}

// Encapsulate generates an ephemeral key on k's curve with crypto/rand and
// returns the ECDH shared secret with k and the ephemeral public key in
// uncompressed form, for crypto.Encapsulator.
func (k *PublicKey) Encapsulate() (sharedKey, ciphertext []byte) {
	e, err := GenerateKey(k.c)
	if err != nil {
		panic("brainpool: " + err.Error())
	}
	shared, err := e.ECDH(k)
	if err != nil {
		panic("brainpool: internal error: " + err.Error())
	}
	return shared, e.pub.Bytes()
}
