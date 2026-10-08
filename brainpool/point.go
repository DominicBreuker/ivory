package brainpool

import (
	"crypto"
	"encoding/hex"
	"errors"

	"filippo.io/bigmod"
)

// curveParams holds a curve's domain parameters in big-endian hex.
type curveParams struct {
	name               string
	p, a, b, gx, gy, n string
}

// curve is a short Weierstrass curve y² = x³ + ax + b over GF(p) with a
// generator G of prime order n and cofactor 1. Field elements and scalars
// are bigmod.Nat values; all have the announced length of p, which equals
// that of n for the Brainpool curves.
type curve struct {
	name string
	size int         // bytes of a field element and of a scalar
	hash crypto.Hash // default hash for the nonce generator

	p, n  *bigmod.Modulus
	a, b3 *bigmod.Nat // a and 3b, mod p
	b     *bigmod.Nat
	g     *point

	pMinus2, nMinus2 []byte // Fermat exponents for inversion
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("brainpool: bad parameter " + s)
	}
	return b
}

func newCurve(cp *curveParams, h crypto.Hash) *curve {
	pb, nb := mustHex(cp.p), mustHex(cp.n)
	p, err := bigmod.NewModulus(pb)
	if err != nil {
		panic(err)
	}
	n, err := bigmod.NewModulus(nb)
	if err != nil {
		panic(err)
	}
	c := &curve{name: cp.name, size: len(pb), hash: h, p: p, n: n}
	if len(nb) != c.size || p.BitLen() != 8*c.size || n.BitLen() != 8*c.size ||
		len(p.Nat().ExpandFor(p).Bits()) != len(n.Nat().ExpandFor(n).Bits()) {
		panic("brainpool: unexpected parameter sizes for " + cp.name)
	}
	c.a = c.mustFieldElement(cp.a)
	c.b = c.mustFieldElement(cp.b)
	c.b3 = c.newFE()
	c.add(c.b3, c.b, c.b)
	c.add(c.b3, c.b3, c.b)
	c.g = &point{c.mustFieldElement(cp.gx), c.mustFieldElement(cp.gy), c.one()}
	c.pMinus2 = minusTwo(pb)
	c.nMinus2 = minusTwo(nb)
	return c
}

func (c *curve) mustFieldElement(h string) *bigmod.Nat {
	x, err := bigmod.NewNat().SetBytes(mustHex(h), c.p)
	if err != nil {
		panic(err)
	}
	return x
}

// minusTwo returns b − 2 for an odd big-endian b > 2.
func minusTwo(b []byte) []byte {
	out := append([]byte(nil), b...)
	borrow := 2
	for i := len(out) - 1; i >= 0 && borrow > 0; i-- {
		v := int(out[i]) - borrow
		borrow = 0
		if v < 0 {
			v += 256
			borrow = 1
		}
		out[i] = byte(v)
	}
	return out
}

// Field arithmetic modulo p. The output may alias the inputs.

func (c *curve) newFE() *bigmod.Nat { return bigmod.NewNat().ExpandFor(c.p) }

func (c *curve) one() *bigmod.Nat {
	x := c.newFE()
	x.Bits()[0] = 1
	return x
}

// setNat sets z = x. Both have the announced length of the modulus.
func setNat(z, x *bigmod.Nat) *bigmod.Nat {
	copy(z.Bits(), x.Bits())
	return z
}

func (c *curve) add(z, x, y *bigmod.Nat) *bigmod.Nat {
	if z == y {
		return z.Add(x, c.p)
	}
	return setNat(z, x).Add(y, c.p)
}

func (c *curve) sub(z, x, y *bigmod.Nat) *bigmod.Nat {
	if z == y {
		t := setNat(c.newFE(), x).Sub(y, c.p)
		return setNat(z, t)
	}
	return setNat(z, x).Sub(y, c.p)
}

func (c *curve) mul(z, x, y *bigmod.Nat) *bigmod.Nat {
	if z == y {
		return z.Mul(x, c.p)
	}
	return setNat(z, x).Mul(y, c.p)
}

// inv sets z = x⁻¹ mod p by Fermat's little theorem, in constant time; the
// inverse of 0 is 0.
func (c *curve) inv(z, x *bigmod.Nat) *bigmod.Nat {
	return z.Exp(x, c.pMinus2, c.p)
}

// condSwap swaps x and y if swap is 1 and leaves them alone if it is 0, in
// constant time. Both have the same announced length.
func condSwap(x, y *bigmod.Nat, swap uint) {
	mask := -swap
	xl, yl := x.Bits(), y.Bits()
	yl = yl[:len(xl)]
	for i := range xl {
		t := mask & (xl[i] ^ yl[i])
		xl[i] ^= t
		yl[i] ^= t
	}
}

// A point in projective coordinates (X : Y : Z), with x = X/Z and y = Y/Z.
// The point at infinity is (0 : 1 : 0), or any (0 : Y : 0).
type point struct{ x, y, z *bigmod.Nat }

func (c *curve) newPoint() *point {
	return &point{c.newFE(), c.one(), c.newFE()}
}

func (c *curve) setPoint(q, r *point) *point {
	setNat(q.x, r.x)
	setNat(q.y, r.y)
	setNat(q.z, r.z)
	return q
}

func condSwapPoints(q, r *point, swap uint) {
	condSwap(q.x, r.x, swap)
	condSwap(q.y, r.y, swap)
	condSwap(q.z, r.z, swap)
}

// addScratch holds the temporaries of addPoints, so that a scalar
// multiplication allocates them once.
type addScratch struct{ t0, t1, t2, t3, t4, t5, x3, y3, z3 *bigmod.Nat }

func (c *curve) newScratch() *addScratch {
	return &addScratch{c.newFE(), c.newFE(), c.newFE(), c.newFE(), c.newFE(),
		c.newFE(), c.newFE(), c.newFE(), c.newFE()}
}

// addPoints sets q = r1 + r2 with the complete addition formulas for
// short Weierstrass curves with arbitrary a of Renes, Costello and Batina,
// "Complete addition formulas for prime order elliptic curves", EUROCRYPT
// 2016 (ePrint 2015/1060), Algorithm 1. The formulas hold for all inputs,
// including r1 = r2 and the point at infinity, on curves of odd order such
// as the Brainpool r1 curves; there are no special cases and no branches.
// q may alias r1 or r2.
//
// The step list was written from the paper from memory (eprint.iacr.org is
// not reachable from our build containers); the tests check it against an
// independent implementation for addition, doubling, inverse points and
// the point at infinity.
func (c *curve) addPoints(q, r1, r2 *point, s *addScratch) *point {
	t0, t1, t2, t3, t4, t5 := s.t0, s.t1, s.t2, s.t3, s.t4, s.t5
	x3, y3, z3 := s.x3, s.y3, s.z3
	x1, y1, z1 := r1.x, r1.y, r1.z
	x2, y2, z2 := r2.x, r2.y, r2.z

	c.mul(t0, x1, x2)   // 1. t0 ← X1·X2
	c.mul(t1, y1, y2)   // 2. t1 ← Y1·Y2
	c.mul(t2, z1, z2)   // 3. t2 ← Z1·Z2
	c.add(t3, x1, y1)   // 4. t3 ← X1+Y1
	c.add(t4, x2, y2)   // 5. t4 ← X2+Y2
	c.mul(t3, t3, t4)   // 6. t3 ← t3·t4
	c.add(t4, t0, t1)   // 7. t4 ← t0+t1
	c.sub(t3, t3, t4)   // 8. t3 ← t3−t4
	c.add(t4, x1, z1)   // 9. t4 ← X1+Z1
	c.add(t5, x2, z2)   // 10. t5 ← X2+Z2
	c.mul(t4, t4, t5)   // 11. t4 ← t4·t5
	c.add(t5, t0, t2)   // 12. t5 ← t0+t2
	c.sub(t4, t4, t5)   // 13. t4 ← t4−t5
	c.add(t5, y1, z1)   // 14. t5 ← Y1+Z1
	c.add(x3, y2, z2)   // 15. X3 ← Y2+Z2
	c.mul(t5, t5, x3)   // 16. t5 ← t5·X3
	c.add(x3, t1, t2)   // 17. X3 ← t1+t2
	c.sub(t5, t5, x3)   // 18. t5 ← t5−X3
	c.mul(z3, c.a, t4)  // 19. Z3 ← a·t4
	c.mul(x3, c.b3, t2) // 20. X3 ← b3·t2
	c.add(z3, x3, z3)   // 21. Z3 ← X3+Z3
	c.sub(x3, t1, z3)   // 22. X3 ← t1−Z3
	c.add(z3, t1, z3)   // 23. Z3 ← t1+Z3
	c.mul(y3, x3, z3)   // 24. Y3 ← X3·Z3
	c.add(t1, t0, t0)   // 25. t1 ← t0+t0
	c.add(t1, t1, t0)   // 26. t1 ← t1+t0
	c.mul(t2, c.a, t2)  // 27. t2 ← a·t2
	c.mul(t4, c.b3, t4) // 28. t4 ← b3·t4
	c.add(t1, t1, t2)   // 29. t1 ← t1+t2
	c.sub(t2, t0, t2)   // 30. t2 ← t0−t2
	c.mul(t2, c.a, t2)  // 31. t2 ← a·t2
	c.add(t4, t4, t2)   // 32. t4 ← t4+t2
	c.mul(t0, t1, t4)   // 33. t0 ← t1·t4
	c.add(y3, y3, t0)   // 34. Y3 ← Y3+t0
	c.mul(t0, t5, t4)   // 35. t0 ← t5·t4
	c.mul(x3, t3, x3)   // 36. X3 ← t3·X3
	c.sub(x3, x3, t0)   // 37. X3 ← X3−t0
	c.mul(t0, t3, t1)   // 38. t0 ← t3·t1
	c.mul(z3, t5, z3)   // 39. Z3 ← t5·Z3
	c.add(z3, z3, t0)   // 40. Z3 ← Z3+t0

	setNat(q.x, x3)
	setNat(q.y, y3)
	setNat(q.z, z3)
	return q
}

// scalarMult returns k·r with a Montgomery ladder over all 8·len(k) bits
// of the big-endian scalar k. The sequence of operations and memory
// accesses depends only on len(k), not on the values of k or r. k may be
// any value, including 0 and multiples of n.
func (c *curve) scalarMult(r *point, k []byte) *point {
	r0 := c.newPoint() // the point at infinity
	r1 := c.setPoint(c.newPoint(), r)
	s := c.newScratch()
	var prev uint
	for _, byt := range k {
		for j := 7; j >= 0; j-- {
			bit := uint(byt>>j) & 1
			condSwapPoints(r0, r1, bit^prev)
			c.addPoints(r1, r0, r1, s)
			c.addPoints(r0, r0, r0, s)
			prev = bit
		}
	}
	condSwapPoints(r0, r1, prev)
	return r0
}

// affine returns the coordinates of q as fixed-length big-endian byte
// strings, or ok = 0 if q is the point at infinity. It runs in constant
// time.
func (c *curve) affine(q *point) (x, y []byte, ok uint) {
	zinv := c.inv(c.newFE(), q.z)
	xa := c.mul(c.newFE(), q.x, zinv)
	ya := c.mul(c.newFE(), q.y, zinv)
	return xa.Bytes(c.p), ya.Bytes(c.p), 1 ^ q.z.IsZero()
}

// pointFromAffine decodes the coordinates x and y, which must be less than
// p and satisfy the curve equation. It is meant for public inputs.
func (c *curve) pointFromAffine(x, y []byte) (*point, error) {
	xn, err := bigmod.NewNat().SetBytes(x, c.p)
	if err != nil {
		return nil, errors.New("brainpool: x-coordinate out of range")
	}
	yn, err := bigmod.NewNat().SetBytes(y, c.p)
	if err != nil {
		return nil, errors.New("brainpool: y-coordinate out of range")
	}
	if c.onCurve(xn, yn) != 1 {
		return nil, errors.New("brainpool: point not on curve")
	}
	return &point{xn, yn, c.one()}, nil
}

// onCurve reports whether y² = x³ + ax + b.
func (c *curve) onCurve(x, y *bigmod.Nat) uint {
	lhs := c.mul(c.newFE(), y, y)
	rhs := c.mul(c.newFE(), x, x)
	c.add(rhs, rhs, c.a)
	c.mul(rhs, rhs, x)
	c.add(rhs, rhs, c.b)
	return lhs.Equal(rhs)
}
