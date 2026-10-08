package brainpool

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"hash"
	"io"

	"filippo.io/bigmod"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Sign signs digest with k and returns an ASN.1 DER ECDSA signature,
// SEQUENCE { r INTEGER, s INTEGER }, for crypto.Signer.
//
// The nonce is derived as in RFC 6979 from the key and the digest, with 32
// bytes from crypto/rand as additional data (RFC 6979, Section 3.6): the
// signature is randomized, and stays safe if the system's randomness
// fails. rand is ignored, as by crypto/ecdsa since Go 1.26. The HMAC-DRBG
// of RFC 6979 uses opts.HashFunc(), or, if opts is nil or names no hash,
// SHA-256, SHA-384 or SHA-512 for P256r1, P384r1 or P512r1. If opts names
// a hash, digest must have its size.
func (k *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := k.sign(digest, opts, true)
	if err != nil {
		return nil, err
	}
	return encodeSignature(r, s)
}

// SignRaw is like PrivateKey.Sign but returns the plain encoding r || s,
// each a big-endian integer of Size(c) bytes (BSI TR-03111, Section 5.2.1;
// IEEE P1363). The nonce generator uses the curve's default hash. rand is
// ignored.
func SignRaw(rand io.Reader, k *PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := k.sign(digest, nil, true)
	if err != nil {
		return nil, err
	}
	return append(r, s...), nil
}

// VerifyASN1 reports whether sig is a valid ASN.1 DER ECDSA signature of
// digest by pub. Non-DER encodings are rejected. A digest longer than the
// order n is truncated to the bit length of n; an empty digest is rejected,
// as by crypto/ecdsa.
func VerifyASN1(pub *PublicKey, digest, sig []byte) bool {
	r, s, err := parseSignature(sig)
	if err != nil {
		return false
	}
	return verify(pub, digest, r, s)
}

// VerifyRaw reports whether rs, the plain encoding r || s of exactly
// 2·Size(c) bytes, is a valid ECDSA signature of digest by pub.
func VerifyRaw(pub *PublicKey, digest, rs []byte) bool {
	if pub == nil || len(rs) != 2*pub.c.size {
		return false
	}
	return verify(pub, digest, rs[:pub.c.size], rs[pub.c.size:])
}

// sign returns r and s as fixed-length big-endian strings. Without
// hedging, the nonce is the deterministic one of RFC 6979.
func (k *PrivateKey) sign(digest []byte, opts crypto.SignerOpts, hedged bool) (r, s []byte, err error) {
	c := k.c
	if len(digest) == 0 {
		return nil, nil, errors.New("brainpool: digest is empty")
	}
	h := c.hash
	if opts != nil && opts.HashFunc() != 0 {
		h = opts.HashFunc()
		if len(digest) != h.Size() {
			return nil, nil, errors.New("brainpool: digest length doesn't match the hash function")
		}
	}
	if !h.Available() {
		return nil, nil, errors.New("brainpool: hash function not available")
	}
	var extra []byte
	if hedged {
		extra = make([]byte, 32)
		if _, err := rand.Read(extra); err != nil {
			return nil, nil, err
		}
	}

	e := hashToNat(c, digest)
	drbg := newNonceGenerator(c, h, k.d, e.Bytes(c.n), extra)
	for {
		kb, kn := drbg.next()

		// r = x(k·G) mod n
		x, _, ok := c.affine(c.scalarMult(c.g, kb))
		if ok != 1 {
			panic("brainpool: internal error: k·G is the point at infinity")
		}
		rn := bigmod.NewNat().Mod(natFromBytes(c, x), c.n)
		if rn.IsZero() == 1 {
			continue
		}

		// s = k⁻¹ · (e + r·d) mod n
		kinv := bigmod.NewNat().Exp(kn, c.nMinus2, c.n)
		sn := setNat(bigmod.NewNat().ExpandFor(c.n), rn).Mul(k.dn, c.n)
		sn.Add(e, c.n)
		sn.Mul(kinv, c.n)
		if sn.IsZero() == 1 {
			continue
		}
		return rn.Bytes(c.n), sn.Bytes(c.n), nil
	}
}

// natFromBytes returns the fixed-length big-endian b, which is less than
// p, as a field element.
func natFromBytes(c *curve, b []byte) *bigmod.Nat {
	x, err := bigmod.NewNat().SetBytes(b, c.p)
	if err != nil {
		panic("brainpool: internal error: coordinate out of range")
	}
	return x
}

func verify(pub *PublicKey, digest, r, s []byte) bool {
	if pub == nil || len(digest) == 0 {
		return false
	}
	c := pub.c
	rn, err := bigmod.NewNat().SetBytes(r, c.n)
	if err != nil || rn.IsZero() == 1 {
		return false
	}
	sn, err := bigmod.NewNat().SetBytes(s, c.n)
	if err != nil || sn.IsZero() == 1 {
		return false
	}
	e := hashToNat(c, digest)

	// w = s⁻¹, u1 = e·w, u2 = r·w mod n
	w := bigmod.NewNat().Exp(sn, c.nMinus2, c.n)
	u1 := setNat(bigmod.NewNat().ExpandFor(c.n), e).Mul(w, c.n)
	u2 := setNat(bigmod.NewNat().ExpandFor(c.n), rn).Mul(w, c.n)

	// The inputs are public, but the constant-time ladder is fast enough.
	p := c.scalarMult(c.g, u1.Bytes(c.n))
	c.addPoints(p, p, c.scalarMult(pub.q, u2.Bytes(c.n)), c.newScratch())
	x, _, ok := c.affine(p)
	if ok != 1 {
		return false
	}
	v := bigmod.NewNat().Mod(natFromBytes(c, x), c.n)
	return v.Equal(rn) == 1
}

// bits2int returns the leftmost qlen bits of b as a big-endian string of
// Size(c) bytes, without reduction (RFC 6979, Section 2.3.2). qlen is the
// bit length of n.
func bits2int(c *curve, b []byte) []byte {
	size := c.size
	if len(b) >= size {
		b = b[:size]
		if excess := len(b)*8 - c.n.BitLen(); excess > 0 {
			// Not reached for the Brainpool curves, whose orders are
			// exactly 8·size bits long.
			b = append([]byte(nil), b...)
			for i := len(b) - 1; i >= 0; i-- {
				b[i] >>= excess
				if i > 0 {
					b[i] |= b[i-1] << (8 - excess)
				}
			}
		}
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// hashToNat returns bits2int(digest) mod n, the integer e of ECDSA and
// bits2octets of RFC 6979, Section 2.3.4.
func hashToNat(c *curve, digest []byte) *bigmod.Nat {
	e, err := bigmod.NewNat().SetOverflowingBytes(bits2int(c, digest), c.n)
	if err != nil {
		panic("brainpool: internal error: truncated hash is too long")
	}
	return e
}

// nonceGenerator is the HMAC-DRBG of RFC 6979, Section 3.2, with optional
// additional data k' (Section 3.6).
type nonceGenerator struct {
	c    *curve
	h    func() hash.Hash
	k, v []byte
}

func newNonceGenerator(c *curve, h crypto.Hash, d, h1 []byte, extra []byte) *nonceGenerator {
	g := &nonceGenerator{c: c, h: h.New}
	size := h.Size()
	g.v = make([]byte, size) // b. V = 0x01 0x01 … 0x01
	for i := range g.v {
		g.v[i] = 1
	}
	g.k = make([]byte, size) // c. K = 0x00 0x00 … 0x00
	// d.–g. K = HMAC_K(V || 0x00/0x01 || int2octets(x) || bits2octets(h1) || k'),
	// V = HMAC_K(V)
	for _, sep := range []byte{0, 1} {
		g.k = g.mac(g.v, []byte{sep}, d, h1, extra)
		g.v = g.mac(g.v)
	}
	return g
}

func (g *nonceGenerator) mac(parts ...[]byte) []byte {
	m := hmac.New(g.h, g.k)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// next returns the next nonce k with 1 ≤ k < n (RFC 6979, Section 3.2,
// step h), as bytes and as a Nat modulo n.
func (g *nonceGenerator) next() ([]byte, *bigmod.Nat) {
	c := g.c
	for {
		var t []byte
		for len(t) < c.size {
			g.v = g.mac(g.v)
			t = append(t, g.v...)
		}
		kb := bits2int(c, t)
		kn, err := bigmod.NewNat().SetBytes(kb, c.n)
		if err == nil && kn.IsZero() == 0 {
			return kb, kn
		}
		g.k = g.mac(g.v, []byte{0})
		g.v = g.mac(g.v)
	}
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes adds a positive integer given as a big-endian string,
// possibly with leading zeros, as a DER INTEGER.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("brainpool: invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// parseSignature parses a strict DER ECDSA signature. r and s are
// non-negative and minimally encoded, without the sign byte.
func parseSignature(sig []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("brainpool: invalid ASN.1 signature")
	}
	return r, s, nil
}
