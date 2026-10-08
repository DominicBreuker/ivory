package brainpool_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
	pmbrainpool "github.com/ProtonMail/go-crypto/brainpool"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var curves = []struct {
	c    brainpool.Curve
	ref  elliptic.Curve // ProtonMail's implementation, variable time
	hash crypto.Hash
}{
	{brainpool.P256r1(), pmbrainpool.P256r1(), crypto.SHA256},
	{brainpool.P384r1(), pmbrainpool.P384r1(), crypto.SHA384},
	{brainpool.P512r1(), pmbrainpool.P512r1(), crypto.SHA512},
}

// Static checks of the interfaces the keys implement.
var (
	_ crypto.Signer       = (*brainpool.PrivateKey)(nil)
	_ crypto.Decapsulator = (*brainpool.PrivateKey)(nil)
	_ crypto.Encapsulator = (*brainpool.PublicKey)(nil)
)

func digest(h crypto.Hash, msg []byte) []byte {
	hh := h.New()
	hh.Write(msg)
	return hh.Sum(nil)
}

func TestCurves(t *testing.T) {
	for _, tt := range curves {
		if got := tt.c.String(); got != tt.ref.Params().Name {
			t.Errorf("String() = %q, want %q", got, tt.ref.Params().Name)
		}
		if got := brainpool.Size(tt.c); got*8 != tt.ref.Params().BitSize {
			t.Errorf("%v: Size = %d", tt.c, got)
		}
	}
	if brainpool.P256r1() != brainpool.P256r1() || brainpool.P256r1() == brainpool.P384r1() {
		t.Error("curves don't compare with ==")
	}
}

func TestNewPrivateKey(t *testing.T) {
	for _, tt := range curves {
		t.Run(tt.c.String(), func(t *testing.T) {
			size := brainpool.Size(tt.c)
			n := tt.ref.Params().N
			fixed := func(v *big.Int) []byte { return v.FillBytes(make([]byte, size)) }
			for _, bad := range [][]byte{
				nil, make([]byte, size), fixed(n), fixed(new(big.Int).Add(n, big.NewInt(1))),
				bytes.Repeat([]byte{0xff}, size), make([]byte, size-1), make([]byte, size+1),
			} {
				if _, err := brainpool.NewPrivateKey(tt.c, bad); err == nil {
					t.Errorf("NewPrivateKey(%x) succeeded", bad)
				}
			}
			for _, d := range [][]byte{fixed(big.NewInt(1)), fixed(new(big.Int).Sub(n, big.NewInt(1)))} {
				k, err := brainpool.NewPrivateKey(tt.c, d)
				if err != nil {
					t.Fatalf("NewPrivateKey(%x): %v", d, err)
				}
				x, y := tt.ref.ScalarBaseMult(d)
				want := elliptic.Marshal(tt.ref, x, y) //nolint:staticcheck // reference only
				if !bytes.Equal(k.PublicKey().Bytes(), want) {
					t.Errorf("public key of %x = %x, want %x", d, k.PublicKey().Bytes(), want)
				}
				if !bytes.Equal(k.Bytes(), d) || k.Curve() != tt.c || k.PublicKey().Curve() != tt.c {
					t.Error("Bytes or Curve wrong")
				}
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	for _, tt := range curves {
		k1, err := brainpool.GenerateKey(tt.c)
		if err != nil {
			t.Fatal(err)
		}
		k2, err := brainpool.GenerateKey(tt.c)
		if err != nil {
			t.Fatal(err)
		}
		if k1.Equal(k2) || k1.PublicKey().Equal(k2.PublicKey()) {
			t.Error("two generated keys are equal")
		}
		k3, err := brainpool.NewPrivateKey(tt.c, k1.Bytes())
		if err != nil || !k1.Equal(k3) || !k1.PublicKey().Equal(k3.Public()) {
			t.Error("a key doesn't round-trip through Bytes")
		}
		if !tt.ref.IsOnCurve(new(big.Int).SetBytes(k1.PublicKey().Bytes()[1:1+brainpool.Size(tt.c)]),
			new(big.Int).SetBytes(k1.PublicKey().Bytes()[1+brainpool.Size(tt.c):])) {
			t.Error("the public key is not on the reference curve")
		}
	}
}

func TestNewPublicKey(t *testing.T) {
	for _, tt := range curves {
		t.Run(tt.c.String(), func(t *testing.T) {
			size := brainpool.Size(tt.c)
			k, err := brainpool.GenerateKey(tt.c)
			if err != nil {
				t.Fatal(err)
			}
			good := k.PublicKey().Bytes()
			pub, err := brainpool.NewPublicKey(tt.c, good)
			if err != nil || !pub.Equal(k.PublicKey()) {
				t.Fatalf("NewPublicKey(good) = %v, %v", pub, err)
			}
			p := tt.ref.Params().P
			offCurve := bytes.Clone(good)
			offCurve[len(offCurve)-1] ^= 1
			xTooBig := bytes.Clone(good)
			copy(xTooBig[1:1+size], bytes.Repeat([]byte{0xff}, size))
			// (x, y + p) has the same residues but y >= p.
			y := new(big.Int).SetBytes(good[1+size:])
			yPlusP := new(big.Int).Add(y, p)
			var yBig []byte
			if yPlusP.BitLen() <= 8*size {
				yBig = append(bytes.Clone(good[:1+size]), yPlusP.FillBytes(make([]byte, size))...)
			}
			compressed := append([]byte{2 + byte(y.Bit(0))}, good[1:1+size]...)
			other := curves[(indexOf(tt.c)+1)%len(curves)].c
			for name, b := range map[string][]byte{
				"off curve":  offCurve,
				"x >= p":     xTooBig,
				"y + p":      yBig,
				"compressed": compressed,
				"hybrid":     append([]byte{6 + byte(y.Bit(0))}, good[1:]...),
				"short":      good[:len(good)-1],
				"long":       append(bytes.Clone(good), 0),
				"empty":      nil,
				"infinity":   {0},
				"zeros":      append([]byte{4}, make([]byte, 2*size)...),
			} {
				if b == nil && name == "y + p" {
					continue
				}
				if _, err := brainpool.NewPublicKey(tt.c, b); err == nil {
					t.Errorf("%s: NewPublicKey succeeded", name)
				}
			}
			if _, err := brainpool.NewPublicKey(other, good); err == nil {
				t.Error("accepted a point of another curve's size")
			}
		})
	}
}

func indexOf(c brainpool.Curve) int {
	for i, tt := range curves {
		if tt.c == c {
			return i
		}
	}
	panic("unknown curve")
}

// legacyKey returns k as a crypto/ecdsa key on ProtonMail's custom curve,
// the deprecated math/big path of crypto/ecdsa, as an independent ECDSA.
func legacyKey(t testing.TB, ref elliptic.Curve, k *brainpool.PrivateKey) *ecdsa.PrivateKey {
	t.Helper()
	b := k.PublicKey().Bytes()
	size := (len(b) - 1) / 2
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: ref, X: new(big.Int).SetBytes(b[1 : 1+size]), Y: new(big.Int).SetBytes(b[1+size:])},
		D:         new(big.Int).SetBytes(k.Bytes()),
	}
}

func TestECDSA(t *testing.T) {
	for _, tt := range curves {
		t.Run(tt.c.String(), func(t *testing.T) {
			k, err := brainpool.GenerateKey(tt.c)
			if err != nil {
				t.Fatal(err)
			}
			pub := k.PublicKey()
			msg := []byte("ivory brainpool ECDSA")
			for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				d := digest(h, msg)
				sig, err := k.Sign(rand.Reader, d, h)
				if err != nil {
					t.Fatal(err)
				}
				if !brainpool.VerifyASN1(pub, d, sig) {
					t.Errorf("%v: own signature doesn't verify", h)
				}
				// The legacy crypto/ecdsa path on ProtonMail's curve
				// verifies ours, and we verify its signatures.
				legacy := legacyKey(t, tt.ref, k)
				if !ecdsa.VerifyASN1(&legacy.PublicKey, d, sig) {
					t.Errorf("%v: crypto/ecdsa (reference curve) rejects our signature", h)
				}
				theirs, err := ecdsa.SignASN1(rand.Reader, legacy, d)
				if err != nil {
					t.Fatal(err)
				}
				if !brainpool.VerifyASN1(pub, d, theirs) {
					t.Errorf("%v: we reject crypto/ecdsa's signature", h)
				}
				bad := bytes.Clone(d)
				bad[0] ^= 1
				if brainpool.VerifyASN1(pub, bad, sig) {
					t.Errorf("%v: signature verifies for another digest", h)
				}
			}

			// Raw r || s.
			d := digest(tt.hash, msg)
			raw, err := brainpool.SignRaw(rand.Reader, k, d)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != 2*brainpool.Size(tt.c) || !brainpool.VerifyRaw(pub, d, raw) {
				t.Error("SignRaw/VerifyRaw round trip failed")
			}
			if brainpool.VerifyRaw(pub, d, raw[1:]) || brainpool.VerifyRaw(pub, d, append(raw, 0)) {
				t.Error("VerifyRaw accepted a wrong length")
			}
			der := derFromRaw(raw)
			if !brainpool.VerifyASN1(pub, d, der) {
				t.Error("the DER form of a raw signature doesn't verify")
			}

			// A key on another curve.
			other, _ := brainpool.GenerateKey(curves[(indexOf(tt.c)+1)%len(curves)].c)
			if brainpool.VerifyASN1(other.PublicKey(), d, der) {
				t.Error("verified with a key on another curve")
			}
			if brainpool.VerifyASN1(nil, d, der) || brainpool.VerifyRaw(nil, d, raw) {
				t.Error("verified with a nil key")
			}

			// The digest length must match opts.
			if _, err := k.Sign(rand.Reader, d[:len(d)-1], tt.hash); err == nil {
				t.Error("Sign accepted a digest of the wrong length")
			}
			if sig, err := k.Sign(rand.Reader, []byte("short"), nil); err != nil || !brainpool.VerifyASN1(pub, []byte("short"), sig) {
				t.Errorf("Sign with nil opts: %v", err)
			}
		})
	}
}

// derFromRaw encodes r || s as DER.
func derFromRaw(raw []byte) []byte {
	half := len(raw) / 2
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(raw[:half]))
		b.AddASN1BigInt(new(big.Int).SetBytes(raw[half:]))
	})
	return b.BytesOrPanic()
}

// TestSignatureEncoding checks that only strict DER is accepted, and that
// r and s outside [1, n−1] are rejected.
func TestSignatureEncoding(t *testing.T) {
	tt := curves[0]
	k, _ := brainpool.GenerateKey(tt.c)
	d := digest(crypto.SHA256, []byte("encoding"))
	raw, _ := brainpool.SignRaw(rand.Reader, k, d)
	r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
	n := tt.ref.Params().N
	enc := func(f func(b *cryptobyte.Builder)) []byte {
		var b cryptobyte.Builder
		f(&b)
		return b.BytesOrPanic()
	}
	seq := func(r, s *big.Int) []byte {
		return enc(func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1BigInt(r); b.AddASN1BigInt(s) })
		})
	}
	good := seq(r, s)
	if !brainpool.VerifyASN1(k.PublicKey(), d, good) {
		t.Fatal("good signature rejected")
	}
	// r with a superfluous leading zero byte.
	rBytes := r.Bytes()
	padded := enc(func(b *cryptobyte.Builder) {
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.INTEGER, func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddUint8(0); b.AddBytes(rBytes) })
			b.AddASN1BigInt(s)
		})
	})
	// BER long-form length for the SEQUENCE.
	longLen := append([]byte{0x30, 0x81, good[1]}, good[2:]...)
	for name, sig := range map[string][]byte{
		"trailing data":    append(bytes.Clone(good), 0),
		"padded integer":   padded,
		"long-form length": longLen,
		"r = 0":            seq(big.NewInt(0), s),
		"s = 0":            seq(r, big.NewInt(0)),
		"r = n":            seq(n, s),
		"s = n":            seq(r, n),
		"r + n":            seq(new(big.Int).Add(r, n), s),
		"s + n":            seq(r, new(big.Int).Add(s, n)),
		"negative r":       seq(new(big.Int).Neg(r), s),
		"empty":            nil,
		"only r": enc(func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1BigInt(r) })
		}),
		"swapped r and s":    seq(s, r),
		"SET instead of SEQ": append([]byte{0x31}, good[1:]...),
	} {
		if brainpool.VerifyASN1(k.PublicKey(), d, sig) {
			t.Errorf("%s: accepted", name)
		}
	}
	// ECDSA signatures are malleable: (r, n − s) is valid too, as in
	// crypto/ecdsa and Wycheproof ("signature malleability").
	if !brainpool.VerifyASN1(k.PublicKey(), d, seq(r, new(big.Int).Sub(n, s))) {
		t.Error("(r, n − s) rejected")
	}
}

// TestHashTruncation checks digests longer and shorter than the order.
func TestHashTruncation(t *testing.T) {
	for _, tt := range curves {
		k, _ := brainpool.GenerateKey(tt.c)
		legacy := legacyKey(t, tt.ref, k)
		for _, d := range [][]byte{
			bytes.Repeat([]byte{0xab}, 64), // SHA-512 size, longer than n for P256r1/P384r1
			bytes.Repeat([]byte{0xcd}, 20), // SHA-1 size
			{1},
		} {
			sig, err := brainpool.SignRaw(rand.Reader, k, d)
			if err != nil {
				t.Fatal(err)
			}
			der := derFromRaw(sig)
			if !brainpool.VerifyASN1(k.PublicKey(), d, der) || !ecdsa.VerifyASN1(&legacy.PublicKey, d, der) {
				t.Errorf("%v: digest of %d bytes: signature rejected", tt.c, len(d))
			}
		}
		// Empty digests are rejected, as by crypto/ecdsa.
		if _, err := brainpool.SignRaw(rand.Reader, k, nil); err == nil {
			t.Error("signed an empty digest")
		}
		sig, _ := brainpool.SignRaw(rand.Reader, k, []byte{0})
		if brainpool.VerifyASN1(k.PublicKey(), nil, derFromRaw(sig)) || brainpool.VerifyRaw(k.PublicKey(), nil, sig) {
			t.Error("verified an empty digest")
		}
	}
}

func TestECDH(t *testing.T) {
	for _, tt := range curves {
		t.Run(tt.c.String(), func(t *testing.T) {
			a, _ := brainpool.GenerateKey(tt.c)
			b, _ := brainpool.GenerateKey(tt.c)
			s1, err := a.ECDH(b.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			s2, err := b.ECDH(a.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			pb := b.PublicKey().Bytes()
			size := brainpool.Size(tt.c)
			x, _ := tt.ref.ScalarMult(new(big.Int).SetBytes(pb[1:1+size]), new(big.Int).SetBytes(pb[1+size:]), a.Bytes())
			want := x.FillBytes(make([]byte, size))
			if !bytes.Equal(s1, s2) || !bytes.Equal(s1, want) {
				t.Errorf("shared secrets %x, %x, reference %x", s1, s2, want)
			}
			other, _ := brainpool.GenerateKey(curves[(indexOf(tt.c)+1)%len(curves)].c)
			if _, err := a.ECDH(other.PublicKey()); err == nil {
				t.Error("ECDH with a key on another curve succeeded")
			}
			if _, err := a.ECDH(nil); err == nil {
				t.Error("ECDH with a nil key succeeded")
			}
		})
	}
}

func TestKEM(t *testing.T) {
	for _, tt := range curves {
		t.Run(tt.c.String(), func(t *testing.T) {
			dk, err := brainpool.GenerateKey(tt.c)
			if err != nil {
				t.Fatal(err)
			}
			ek, err := brainpool.NewPublicKey(tt.c, dk.Encapsulator().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			shared, ct := ek.Encapsulate()
			got, err := dk.Decapsulate(ct)
			if err != nil || !bytes.Equal(got, shared) {
				t.Errorf("Decapsulate = %x, %v; want %x", got, err, shared)
			}
			shared2, ct2 := ek.Encapsulate()
			if bytes.Equal(ct, ct2) || bytes.Equal(shared, shared2) {
				t.Error("Encapsulate reused its ephemeral key")
			}
			bad := bytes.Clone(ct)
			bad[len(bad)-1] ^= 1
			if _, err := dk.Decapsulate(bad); err == nil {
				t.Error("Decapsulate accepted a point off the curve")
			}
			if _, err := dk.Decapsulate(ct[:1+brainpool.Size(tt.c)]); err == nil {
				t.Error("Decapsulate accepted a truncated point")
			}
		})
	}
}

// TestSignerInterface checks Sign through crypto.Signer with a SHA-512
// digest on brainpoolP256r1, as crypto/tls does for scheme 0x0603.
func TestSignerInterface(t *testing.T) {
	k, _ := brainpool.GenerateKey(brainpool.P256r1())
	var signer crypto.Signer = k
	d := sha512.Sum512([]byte("transcript"))
	sig, err := signer.Sign(rand.Reader, d[:], crypto.SHA512)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := signer.Public().(*brainpool.PublicKey)
	if !ok || !brainpool.VerifyASN1(pub, d[:], sig) {
		t.Error("crypto.Signer signature doesn't verify")
	}
	d256 := sha256.Sum256([]byte("transcript"))
	if brainpool.VerifyASN1(pub, d256[:], sig) {
		t.Error("verified with another digest")
	}
}
