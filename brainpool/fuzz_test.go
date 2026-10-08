package brainpool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"math/big"
	"testing"
)

func fuzzCurve(i byte) *curve { return allCurves[int(i)%len(allCurves)] }

// fixedScalar left-pads or truncates (keeping the low bytes) k to size.
func fixedScalar(k []byte, size int) []byte {
	if len(k) >= size {
		return k[len(k)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(k):], k)
	return out
}

// FuzzScalarMult compares k·G and k·Q with the reference implementation.
func FuzzScalarMult(f *testing.F) {
	f.Add(byte(0), []byte{1})
	f.Add(byte(1), bytes.Repeat([]byte{0xff}, 48))
	f.Add(byte(2), []byte{})
	for _, c := range allCurves {
		f.Add(byte(0), mustHex(paramsOf(c).n))
	}
	f.Fuzz(func(t *testing.T, ci byte, k []byte) {
		c := fuzzCurve(ci)
		ref := reference(c)
		k = fixedScalar(k, c.size)

		wantX, wantY := ref.ScalarBaseMult(k)
		gotX, gotY := fromPoint(c, c.scalarMult(c.g, k))
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatalf("%s: k·G for k = %x: got (%x, %x), want (%x, %x)", c.name, k, gotX, gotY, wantX, wantY)
		}

		// Q = h·G for a scalar h derived from k, then k·Q.
		h := sha512.Sum512(k)
		qx, qy := ref.ScalarBaseMult(h[:c.size])
		if qx.Sign() == 0 && qy.Sign() == 0 {
			return
		}
		wantX, wantY = ref.ScalarMult(qx, qy, k)
		gotX, gotY = fromPoint(c, c.scalarMult(toPoint(t, c, qx, qy), k))
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatalf("%s: k·Q for k = %x: got (%x, %x), want (%x, %x)", c.name, k, gotX, gotY, wantX, wantY)
		}
	})
}

// FuzzNewPublicKey checks that NewPublicKey never panics, accepts exactly
// the uncompressed points the reference considers on the curve, and
// round-trips them.
func FuzzNewPublicKey(f *testing.F) {
	for i, c := range allCurves {
		k, _ := GenerateKey(c)
		f.Add(byte(i), k.PublicKey().Bytes())
	}
	f.Add(byte(0), []byte{4})
	f.Add(byte(1), []byte{0})
	f.Fuzz(func(t *testing.T, ci byte, b []byte) {
		c := fuzzCurve(ci)
		pub, err := NewPublicKey(c, b)
		if err == nil && !bytes.Equal(pub.Bytes(), b) {
			t.Fatalf("Bytes() = %x, input %x", pub.Bytes(), b)
		}
		if len(b) != 1+2*c.size || b[0] != 4 {
			if err == nil {
				t.Fatalf("accepted encoding %x", b)
			}
			return
		}
		ref := reference(c)
		x := new(big.Int).SetBytes(b[1 : 1+c.size])
		y := new(big.Int).SetBytes(b[1+c.size:])
		p := ref.Params().P
		want := x.Cmp(p) < 0 && y.Cmp(p) < 0 && onCurveBig(paramsOf(c), t, x, y)
		if want != (err == nil) {
			t.Fatalf("NewPublicKey(%x) err = %v, reference on curve = %v", b, err, want)
		}
	})
}

// FuzzVerifyASN1 compares VerifyASN1 with crypto/ecdsa's legacy
// verification on the reference curve, for a key derived from seed.
func FuzzVerifyASN1(f *testing.F) {
	for i, c := range allCurves {
		var seed []byte
		var k *PrivateKey
		for j := 0; k == nil; j++ {
			seed = []byte{byte(i), byte(j)}
			k = fuzzKey(c, seed)
		}
		d := sha512.Sum512([]byte("fuzz"))
		sig, _ := k.Sign(nil, d[:c.size], nil)
		f.Add(byte(i), seed, d[:c.size], sig)
		f.Add(byte(i), seed, d[:], sig)
	}
	f.Fuzz(func(t *testing.T, ci byte, seed, digest, sig []byte) {
		c := fuzzCurve(ci)
		k := fuzzKey(c, seed)
		if k == nil {
			return
		}
		got := VerifyASN1(k.PublicKey(), digest, sig)
		b := k.PublicKey().Bytes()
		legacy := &ecdsa.PublicKey{Curve: reference(c),
			X: new(big.Int).SetBytes(b[1 : 1+c.size]), Y: new(big.Int).SetBytes(b[1+c.size:])}
		want := len(digest) > 0 && ecdsa.VerifyASN1(legacy, digest, sig)
		if got != want {
			t.Fatalf("%s: VerifyASN1 = %v, crypto/ecdsa (reference curve) = %v; digest %x, sig %x", c.name, got, want, digest, sig)
		}
	})
}

// fuzzKey derives a key from seed, or returns nil if the derived scalar is
// out of range.
func fuzzKey(c *curve, seed []byte) *PrivateKey {
	h := sha512.Sum512(seed)
	k, err := NewPrivateKey(c, h[:c.size])
	if err != nil {
		return nil
	}
	return k
}
