package brainpool

// Tests of the arithmetic against math/big (tests only) and against
// github.com/ProtonMail/go-crypto/brainpool, an independent implementation
// of the same curves (math/big, variable time) that also serves as the
// reference for the curve parameters.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"testing"

	pmbrainpool "github.com/ProtonMail/go-crypto/brainpool"
)

var allCurves = []*curve{p256r1, p384r1, p512r1}

// reference returns ProtonMail's implementation of c.
func reference(c *curve) elliptic.Curve {
	switch c {
	case p256r1:
		return pmbrainpool.P256r1()
	case p384r1:
		return pmbrainpool.P384r1()
	case p512r1:
		return pmbrainpool.P512r1()
	}
	panic("unknown curve")
}

func bigOf(t testing.TB, h string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		t.Fatalf("bad hex %q", h)
	}
	return v
}

func paramsOf(c *curve) *curveParams {
	switch c {
	case p256r1:
		return &p256r1Params
	case p384r1:
		return &p384r1Params
	case p512r1:
		return &p512r1Params
	}
	panic("unknown curve")
}

// onCurveBig checks y² = x³ + ax + b mod p with math/big.
func onCurveBig(cp *curveParams, t testing.TB, x, y *big.Int) bool {
	p, a, b := bigOf(t, cp.p), bigOf(t, cp.a), bigOf(t, cp.b)
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, p)
	rhs := new(big.Int).Mul(x, x)
	rhs.Add(rhs, a)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, b)
	rhs.Mod(rhs, p)
	return lhs.Cmp(rhs) == 0
}

func TestCurveParameters(t *testing.T) {
	for _, c := range allCurves {
		t.Run(c.name, func(t *testing.T) {
			cp := paramsOf(c)
			p, a, n := bigOf(t, cp.p), bigOf(t, cp.a), bigOf(t, cp.n)
			gx, gy := bigOf(t, cp.gx), bigOf(t, cp.gy)

			if !p.ProbablyPrime(32) || !n.ProbablyPrime(32) {
				t.Error("p or n is not prime")
			}
			if new(big.Int).Sub(p, big.NewInt(3)).Cmp(a) == 0 {
				t.Error("a = −3; the r1 curves have a random a")
			}
			// Hasse: |p + 1 − n| ≤ 2√p, with cofactor 1.
			tr := new(big.Int).Add(p, big.NewInt(1))
			tr.Sub(tr, n).Abs(tr)
			if tr.Mul(tr, tr).Cmp(new(big.Int).Lsh(p, 2)) > 0 {
				t.Error("n is outside the Hasse interval")
			}
			if p.BitLen() != 8*c.size || n.BitLen() != 8*c.size {
				t.Errorf("bit lengths %d, %d, want %d", p.BitLen(), n.BitLen(), 8*c.size)
			}
			if !onCurveBig(cp, t, gx, gy) {
				t.Error("G is not on the curve (math/big)")
			}
			if c.onCurve(c.g.x, c.g.y) != 1 {
				t.Error("G is not on the curve (bigmod)")
			}
			// 3b
			b3 := new(big.Int).Mul(bigOf(t, cp.b), big.NewInt(3))
			b3.Mod(b3, p)
			if !bytes.Equal(c.b3.Bytes(c.p), b3.FillBytes(make([]byte, c.size))) {
				t.Error("b3 != 3b mod p")
			}
			// n·G is the point at infinity; (n−1)·G = −G.
			if _, _, ok := c.affine(c.scalarMult(c.g, n.FillBytes(make([]byte, c.size)))); ok != 0 {
				t.Error("n·G is not the point at infinity")
			}
			x, y, ok := c.affine(c.scalarMult(c.g, new(big.Int).Sub(n, big.NewInt(1)).FillBytes(make([]byte, c.size))))
			negGy := new(big.Int).Sub(p, gy)
			if ok != 1 || new(big.Int).SetBytes(x).Cmp(gx) != 0 || new(big.Int).SetBytes(y).Cmp(negGy) != 0 {
				t.Error("(n−1)·G != −G")
			}
		})
	}
}

// TestParametersAgainstReference checks the parameters against ProtonMail's
// package. It has no a and b for the r1 curves (it computes on the twist
// t1), so a and b are checked through two of its points, G and 2G: two
// points with distinct x determine a and b of y² = x³ + ax + b.
func TestParametersAgainstReference(t *testing.T) {
	for _, c := range allCurves {
		t.Run(c.name, func(t *testing.T) {
			cp := paramsOf(c)
			ref := reference(c)
			rp := ref.Params()
			for name, pair := range map[string][2]*big.Int{
				"p": {bigOf(t, cp.p), rp.P}, "n": {bigOf(t, cp.n), rp.N},
				"Gx": {bigOf(t, cp.gx), rp.Gx}, "Gy": {bigOf(t, cp.gy), rp.Gy},
			} {
				if pair[0].Cmp(pair[1]) != 0 {
					t.Errorf("%s differs from the reference", name)
				}
			}
			if rp.Name != c.name || rp.BitSize != 8*c.size {
				t.Errorf("reference name, size = %s, %d", rp.Name, rp.BitSize)
			}
			x2, y2 := ref.Double(rp.Gx, rp.Gy)
			if x2.Cmp(rp.Gx) == 0 {
				t.Fatal("G and 2G have the same x")
			}
			if !onCurveBig(cp, t, rp.Gx, rp.Gy) || !onCurveBig(cp, t, x2, y2) {
				t.Error("the reference's G or 2G is not on our curve")
			}
		})
	}
}

// toPoint converts affine big.Int coordinates, (0, 0) for infinity as in
// crypto/elliptic, to a point.
func toPoint(t testing.TB, c *curve, x, y *big.Int) *point {
	t.Helper()
	if x.Sign() == 0 && y.Sign() == 0 {
		return c.newPoint()
	}
	q, err := c.pointFromAffine(x.FillBytes(make([]byte, c.size)), y.FillBytes(make([]byte, c.size)))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// fromPoint converts q to affine big.Int coordinates, (0, 0) for infinity.
func fromPoint(c *curve, q *point) (*big.Int, *big.Int) {
	x, y, ok := c.affine(q)
	if ok == 0 {
		return new(big.Int), new(big.Int)
	}
	return new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
}

func randomScalar(t testing.TB, c *curve) []byte {
	k, err := GenerateKey(c)
	if err != nil {
		t.Fatal(err)
	}
	return k.Bytes()
}

// TestAddPoints checks the complete formulas against the reference,
// including doubling, inverses and the point at infinity, and with
// projective inputs whose Z is not 1.
func TestAddPoints(t *testing.T) {
	for _, c := range allCurves {
		t.Run(c.name, func(t *testing.T) {
			ref := reference(c)
			rp := ref.Params()
			s := c.newScratch()
			px, py := ref.ScalarBaseMult(randomScalar(t, c))
			qx, qy := ref.ScalarBaseMult(randomScalar(t, c))
			negPy := new(big.Int).Sub(rp.P, py)
			zero := new(big.Int)
			for _, tt := range []struct {
				name           string
				x1, y1, x2, y2 *big.Int
			}{
				{"P+Q", px, py, qx, qy},
				{"P+P", px, py, px, py},
				{"P+(−P)", px, py, px, negPy},
				{"O+P", zero, zero, px, py},
				{"P+O", px, py, zero, zero},
				{"O+O", zero, zero, zero, zero},
				{"G+G", rp.Gx, rp.Gy, rp.Gx, rp.Gy},
			} {
				r1 := toPoint(t, c, tt.x1, tt.y1)
				r2 := toPoint(t, c, tt.x2, tt.y2)
				// Scale r1 by a random λ: (λX : λY : λZ) is the same point.
				lambda := natFromBytes(c, bytes.Repeat([]byte{0x5a}, c.size))
				c.mul(r1.x, r1.x, lambda)
				c.mul(r1.y, r1.y, lambda)
				c.mul(r1.z, r1.z, lambda)

				var wantX, wantY *big.Int
				switch {
				case tt.x1.Sign() == 0 && tt.y1.Sign() == 0:
					wantX, wantY = tt.x2, tt.y2
				case tt.x2.Sign() == 0 && tt.y2.Sign() == 0:
					wantX, wantY = tt.x1, tt.y1
				case tt.x1.Cmp(tt.x2) == 0 && tt.y1.Cmp(tt.y2) != 0:
					wantX, wantY = zero, zero
				case tt.x1.Cmp(tt.x2) == 0:
					wantX, wantY = ref.Double(tt.x1, tt.y1)
				default:
					wantX, wantY = ref.Add(tt.x1, tt.y1, tt.x2, tt.y2)
				}
				gotX, gotY := fromPoint(c, c.addPoints(c.newPoint(), r1, r2, s))
				if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
					t.Errorf("%s = (%x, %x), want (%x, %x)", tt.name, gotX, gotY, wantX, wantY)
				}
				// Aliased output.
				gotX, gotY = fromPoint(c, c.addPoints(r1, r1, r2, s))
				if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
					t.Errorf("%s (aliased) = (%x, %x), want (%x, %x)", tt.name, gotX, gotY, wantX, wantY)
				}
			}
		})
	}
}

// TestScalarMult compares the ladder with the reference for edge-case and
// random scalars, on G and on another point.
func TestScalarMult(t *testing.T) {
	for _, c := range allCurves {
		t.Run(c.name, func(t *testing.T) {
			ref := reference(c)
			rp := ref.Params()
			n := rp.N
			fixed := func(v *big.Int) []byte { return v.FillBytes(make([]byte, c.size)) }
			scalars := [][]byte{
				fixed(big.NewInt(0)), fixed(big.NewInt(1)), fixed(big.NewInt(2)), fixed(big.NewInt(3)),
				fixed(new(big.Int).Sub(n, big.NewInt(1))), fixed(new(big.Int).Sub(n, big.NewInt(2))),
				fixed(n), fixed(new(big.Int).Add(n, big.NewInt(1))),
				bytes.Repeat([]byte{0xff}, c.size),
				append([]byte{0x80}, make([]byte, c.size-1)...),
			}
			for i := 0; i < 8; i++ {
				scalars = append(scalars, randomScalar(t, c))
			}
			qx, qy := ref.ScalarBaseMult(randomScalar(t, c))
			for _, k := range scalars {
				for _, base := range []struct{ x, y *big.Int }{{rp.Gx, rp.Gy}, {qx, qy}} {
					wantX, wantY := ref.ScalarMult(base.x, base.y, k)
					gotX, gotY := fromPoint(c, c.scalarMult(toPoint(t, c, base.x, base.y), k))
					if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
						t.Errorf("k = %x: got (%x, %x), want (%x, %x)", k, gotX, gotY, wantX, wantY)
					}
				}
			}
		})
	}
}

func TestMinusTwo(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"05", "03"}, {"0101", "00ff"}, {"0100", "00fe"}, {"a9fb57", "a9fb55"},
	} {
		in, _ := hex.DecodeString(tt.in)
		if got := hex.EncodeToString(minusTwo(in)); got != tt.want {
			t.Errorf("minusTwo(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestCondSwap(t *testing.T) {
	c := p256r1
	x := natFromBytes(c, bytes.Repeat([]byte{1}, c.size))
	y := natFromBytes(c, bytes.Repeat([]byte{2}, c.size))
	condSwap(x, y, 0)
	if x.Bytes(c.p)[0] != 1 || y.Bytes(c.p)[0] != 2 {
		t.Error("condSwap(0) swapped")
	}
	condSwap(x, y, 1)
	if x.Bytes(c.p)[0] != 2 || y.Bytes(c.p)[0] != 1 {
		t.Error("condSwap(1) didn't swap")
	}
}

// nistP256 is NIST P-256 built with this package's generic code. The
// complete formulas hold for any a, so the RFC 6979 test vectors for P-256
// (Appendix A.2.5) check ECDSA and the nonce generator end to end.
func nistP256(t testing.TB) *curve {
	p := elliptic.P256().Params()
	a := new(big.Int).Sub(p.P, big.NewInt(3))
	h := func(v *big.Int) string { return hex.EncodeToString(v.FillBytes(make([]byte, 32))) }
	return newCurve(&curveParams{name: "P-256", p: h(p.P), a: h(a), b: h(p.B), gx: h(p.Gx), gy: h(p.Gy), n: h(p.N)}, crypto.SHA256)
}

func TestRFC6979P256(t *testing.T) {
	c := nistP256(t)
	d, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	k, err := NewPrivateKey(c, d)
	if err != nil {
		t.Fatal(err)
	}
	// Public key U of RFC 6979, Appendix A.2.5.
	wantU := "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
	if got := hex.EncodeToString(k.PublicKey().Bytes()); got != wantU {
		t.Errorf("U = %s, want %s", got, wantU)
	}
	for _, tt := range []struct {
		h    crypto.Hash
		r, s string
	}{
		// RFC 6979, Appendix A.2.5, message "sample". Recomputed with
		// Python cryptography 50.0.1 (deterministic_signing=True).
		{crypto.SHA256, "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"},
		{crypto.SHA512, "8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f00", "2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe"},
	} {
		hh := tt.h.New()
		hh.Write([]byte("sample"))
		digest := hh.Sum(nil)
		r, s, err := k.sign(digest, tt.h, false)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(r) != tt.r || hex.EncodeToString(s) != tt.s {
			t.Errorf("%v: r, s = %x, %x; want %s, %s", tt.h, r, s, tt.r, tt.s)
		}
		// crypto/ecdsa agrees.
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), k.PublicKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)) {
			t.Errorf("%v: crypto/ecdsa rejects the signature", tt.h)
		}
		if !verify(k.PublicKey(), digest, r, s) {
			t.Errorf("%v: verify rejects the signature", tt.h)
		}
	}
}

// TestNonceGenerator checks the HMAC-DRBG loop: a rejected candidate
// leads to the next one, as RFC 6979, Section 3.2, step h.3, says.
func TestNonceGenerator(t *testing.T) {
	c := p256r1
	d := bytes.Repeat([]byte{7}, c.size)
	h1 := sha256.Sum256([]byte("msg"))
	g1 := newNonceGenerator(c, crypto.SHA256, d, h1[:], nil)
	g2 := newNonceGenerator(c, crypto.SHA256, d, h1[:], nil)
	k1, _ := g1.next()
	k2, _ := g2.next()
	if !bytes.Equal(k1, k2) {
		t.Fatal("the generator is not deterministic")
	}
	k3, _ := g1.next()
	if bytes.Equal(k1, k3) {
		t.Error("the second nonce repeats the first")
	}
	g3 := newNonceGenerator(c, crypto.SHA256, d, h1[:], []byte("extra"))
	if k4, _ := g3.next(); bytes.Equal(k1, k4) {
		t.Error("additional data doesn't change the nonce")
	}
	// A 64-byte output and a 32-byte hash: T is two HMAC blocks.
	h5 := sha512.Sum512([]byte("msg"))
	g5 := newNonceGenerator(p512r1, crypto.SHA256, bytes.Repeat([]byte{7}, 64), h5[:], nil)
	if k5, _ := g5.next(); len(k5) != 64 {
		t.Errorf("nonce length %d, want 64", len(k5))
	}
}

// TestDeterministicAgainstPython compares deterministic (unhedged) RFC 6979
// signatures on the Brainpool curves with Python cryptography.
func TestDeterministicAgainstPython(t *testing.T) {
	type sigCase struct {
		curve *curve
		h     crypto.Hash
		pyH   string
	}
	cases := []sigCase{
		{p256r1, crypto.SHA256, "SHA256"}, {p256r1, crypto.SHA384, "SHA384"},
		{p384r1, crypto.SHA384, "SHA384"}, {p512r1, crypto.SHA512, "SHA512"},
		{p512r1, crypto.SHA256, "SHA256"},
	}
	for _, tt := range cases {
		k, err := GenerateKey(tt.curve)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("ivory deterministic ECDSA")
		hh := tt.h.New()
		hh.Write(msg)
		r, s, err := k.sign(hh.Sum(nil), tt.h, false)
		if err != nil {
			t.Fatal(err)
		}
		py := pythonDeterministic(t, tt.curve.name, tt.pyH, k.Bytes(), msg)
		if want := hex.EncodeToString(append(r, s...)); py != want {
			t.Errorf("%s/%v: Python r||s = %s, want %s", tt.curve.name, tt.h, py, want)
		}
	}
}

func TestHedgedSignatures(t *testing.T) {
	// Hedged signatures of the same digest differ.
	k, err := GenerateKey(p256r1)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	s1, _ := k.Sign(rand.Reader, digest, crypto.SHA256)
	s2, _ := k.Sign(rand.Reader, digest, crypto.SHA256)
	if bytes.Equal(s1, s2) {
		t.Error("two hedged signatures are equal")
	}
	if !VerifyASN1(k.PublicKey(), digest, s1) || !VerifyASN1(k.PublicKey(), digest, s2) {
		t.Error("hedged signature doesn't verify")
	}
}
