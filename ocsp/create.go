package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// A ResponseTemplate describes a response for CreateResponse.
type ResponseTemplate struct {
	// Status is the responseStatus. If it is not Successful, the response
	// consists of the status only and the other fields are ignored.
	Status ResponseStatus

	// ResponderByName selects the responder ID byName (the responder
	// certificate's subject) instead of byKey.
	ResponderByName bool

	ProducedAt time.Time

	// Responses are the single responses. CertID, Status, ThisUpdate are
	// required; a non-nil CertHash is written as certHash extension in
	// front of Extensions. RevocationReason -1 or 0 with a zero RevokedAt
	// is omitted.
	Responses []SingleResponse

	// Extensions are the responseExtensions, for example a nonce.
	Extensions []pkix.Extension

	// Certificates are DER certificates to embed, typically the responder
	// certificate.
	Certificates [][]byte
}

// NewCertHash returns the certHash value for cert with SHA-256, which TI
// responders use (GS-A_4693-01, gemSpec_Krypt GS-A_4393).
func NewCertHash(cert *x509.Certificate) *CertHash {
	h := sha256.Sum256(cert.Raw)
	return &CertHash{HashAlgorithm: crypto.SHA256, Hash: h[:]}
}

// CreateResponse returns a DER OCSP response for t, signed by signer, the
// key of responder. signer may hold a Brainpool, ECDSA or RSA key; the
// signature algorithm is ECDSA with SHA-256, -384 or -512 by curve size,
// or SHA-256 with RSA (PKCS #1 v1.5).
//
// CreateResponse is meant for test responders and simulators: it signs
// whatever the template says.
func CreateResponse(t ResponseTemplate, responder *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if t.Status != Successful {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Enum(int64(t.Status))
		})
		return b.Bytes()
	}
	if len(t.Responses) == 0 {
		return nil, errors.New("ocsp: template without single responses")
	}
	sigAlg, hash, err := signatureParams(signer.Public())
	if err != nil {
		return nil, err
	}
	var tb cryptobyte.Builder
	tb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if t.ResponderByName {
			b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(responder.RawSubject)
			})
		} else {
			h, err := keyHash(responder)
			if err != nil {
				b.SetError(err)
				return
			}
			b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(h)
			})
		}
		b.AddASN1GeneralizedTime(t.ProducedAt.UTC())
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for i := range t.Responses {
				addSingleResponse(b, &t.Responses[i])
			}
		})
		addExtensions(b, 1, t.Extensions)
	})
	tbs, err := tb.Bytes()
	if err != nil {
		return nil, err
	}
	hh := hash.New()
	hh.Write(tbs)
	sig, err := signer.Sign(rand.Reader, hh.Sum(nil), hash)
	if err != nil {
		return nil, err
	}
	var bb cryptobyte.Builder
	bb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(sigAlg)
		b.AddASN1BitString(sig)
		if len(t.Certificates) > 0 {
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, c := range t.Certificates {
						b.AddBytes(c)
					}
				})
			})
		}
	})
	basic, err := bb.Bytes()
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Enum(int64(Successful))
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidBasicResponse)
				b.AddASN1OctetString(basic)
			})
		})
	})
	return b.Bytes()
}

func addSingleResponse(b *cryptobyte.Builder, sr *SingleResponse) {
	if sr.CertID == nil {
		b.SetError(errors.New("ocsp: single response without CertID"))
		return
	}
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		sr.CertID.marshal(b)
		switch sr.Status {
		case Good:
			b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(*cryptobyte.Builder) {})
		case Unknown:
			b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(*cryptobyte.Builder) {})
		case Revoked:
			b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1GeneralizedTime(sr.RevokedAt.UTC())
				if sr.RevocationReason > 0 {
					b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddASN1Enum(int64(sr.RevocationReason))
					})
				}
			})
		default:
			b.SetError(fmt.Errorf("ocsp: bad certificate status %v", sr.Status))
			return
		}
		b.AddASN1GeneralizedTime(sr.ThisUpdate.UTC())
		if !sr.NextUpdate.IsZero() {
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1GeneralizedTime(sr.NextUpdate.UTC())
			})
		}
		exts := sr.Extensions
		if sr.CertHash != nil {
			oid := oidForHash(sr.CertHash.HashAlgorithm)
			if oid == nil {
				b.SetError(errors.New("ocsp: unsupported certHash algorithm"))
				return
			}
			var vb cryptobyte.Builder
			vb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oid)
				})
				b.AddASN1OctetString(sr.CertHash.Hash)
			})
			exts = append([]pkix.Extension{{Id: OIDCertHash, Value: vb.BytesOrPanic()}}, exts...)
		}
		addExtensions(b, 1, exts)
	})
}

func addExtensions(b *cryptobyte.Builder, tag uint8, exts []pkix.Extension) {
	if len(exts) == 0 {
		return
	}
	b.AddASN1(cbasn1.Tag(tag).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, e := range exts {
				addExtension(b, e)
			}
		})
	})
}

// signatureParams returns the DER AlgorithmIdentifier and the hash for
// signing with a key whose public key is pub.
func signatureParams(pub crypto.PublicKey) ([]byte, crypto.Hash, error) {
	var oid []int
	var h crypto.Hash
	null := false
	size := 0
	switch k := pub.(type) {
	case *brainpool.PublicKey:
		size = brainpool.Size(k.Curve())
	case *ecdsa.PublicKey:
		size = (k.Curve.Params().BitSize + 7) / 8
	case *rsa.PublicKey:
		oid, h, null = oidSHA256WithRSA, crypto.SHA256, true
	default:
		return nil, 0, fmt.Errorf("ocsp: unsupported signer key %T", pub)
	}
	if oid == nil {
		switch {
		case size <= 32:
			oid, h = oidECDSAWithSHA256, crypto.SHA256
		case size <= 48:
			oid, h = oidECDSAWithSHA384, crypto.SHA384
		default:
			oid, h = oidECDSAWithSHA512, crypto.SHA512
		}
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if null {
			b.AddASN1NULL()
		}
	})
	der, err := b.Bytes()
	return der, h, err
}
