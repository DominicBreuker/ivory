package brainpool_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
)

func BenchmarkGenerateKey(b *testing.B) {
	for _, tt := range curves {
		b.Run(tt.c.String(), func(b *testing.B) {
			for b.Loop() {
				if _, err := brainpool.GenerateKey(tt.c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkECDH(b *testing.B) {
	for _, tt := range curves {
		b.Run(tt.c.String(), func(b *testing.B) {
			k, _ := brainpool.GenerateKey(tt.c)
			peer, _ := brainpool.GenerateKey(tt.c)
			for b.Loop() {
				if _, err := k.ECDH(peer.PublicKey()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	for _, tt := range curves {
		b.Run(tt.c.String(), func(b *testing.B) {
			k, _ := brainpool.GenerateKey(tt.c)
			d := digest(tt.hash, []byte("benchmark"))
			for b.Loop() {
				if _, err := k.Sign(rand.Reader, d, tt.hash); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, tt := range curves {
		b.Run(tt.c.String(), func(b *testing.B) {
			k, _ := brainpool.GenerateKey(tt.c)
			d := digest(tt.hash, []byte("benchmark"))
			sig, _ := k.Sign(rand.Reader, d, tt.hash)
			for b.Loop() {
				if !brainpool.VerifyASN1(k.PublicKey(), d, sig) {
					b.Fatal("verification failed")
				}
			}
		})
	}
}

// BenchmarkReferenceScalarMult measures ProtonMail's variable-time
// implementation (math/big), for comparison only.
func BenchmarkReferenceScalarMult(b *testing.B) {
	for _, tt := range curves {
		b.Run(tt.c.String(), func(b *testing.B) {
			k, _ := brainpool.GenerateKey(tt.c)
			p := tt.ref.Params()
			for b.Loop() {
				tt.ref.ScalarMult(p.Gx, p.Gy, k.Bytes())
			}
		})
	}
}

// BenchmarkReferenceSign measures crypto/ecdsa's legacy path on
// ProtonMail's curves (variable time), for comparison only.
func BenchmarkReferenceSign(b *testing.B) {
	for _, tt := range curves {
		b.Run(tt.c.String(), func(b *testing.B) {
			k, _ := brainpool.GenerateKey(tt.c)
			legacy := legacyKey(b, tt.ref, k)
			d := digest(tt.hash, []byte("benchmark"))
			for b.Loop() {
				if _, err := ecdsa.SignASN1(rand.Reader, legacy, d); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
