package ocsp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// RequestOptions are the options of CreateRequest.
type RequestOptions struct {
	// Hash is the hash of the CertID. If zero, SHA-1 is used, which every
	// responder supports (RFC 5019, Section 2.1.1; gemSpec_PKI V2.28.0,
	// note to TUC_PKI_006 step 6b).
	Hash crypto.Hash

	// Nonce, if not nil, is sent in a nonce extension (RFC 6960, Section
	// 4.4.1, as an OCTET STRING inside the extension value, RFC 8954).
	Nonce []byte
}

// A Request is a parsed OCSP request.
type Request struct {
	CertIDs []*CertID
	// Extensions are the requestExtensions.
	Extensions []pkix.Extension
}

// Nonce returns the value of the nonce extension of r, or nil.
func (r *Request) Nonce() []byte {
	for _, e := range r.Extensions {
		if e.Id.Equal(OIDNonce) {
			return e.Value
		}
	}
	return nil
}

// CreateRequest returns a DER OCSP request for cert, issued by issuer,
// without a signature. issuer's key may be a Brainpool key.
func CreateRequest(cert, issuer *x509.Certificate, opts *RequestOptions) ([]byte, error) {
	h := crypto.SHA1
	var nonce []byte
	if opts != nil {
		if opts.Hash != 0 {
			h = opts.Hash
		}
		nonce = opts.Nonce
	}
	id, err := NewCertID(cert, issuer, h)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // OCSPRequest
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // TBSRequest
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // requestList
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // Request
					id.marshal(b)
				})
			})
			if nonce != nil {
				b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						addExtension(b, pkix.Extension{Id: OIDNonce, Value: octetString(nonce)})
					})
				})
			}
		})
	})
	return b.Bytes()
}

func octetString(v []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1OctetString(v)
	return b.BytesOrPanic()
}

func addExtension(b *cryptobyte.Builder, e pkix.Extension) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(e.Id)
		if e.Critical {
			b.AddASN1Boolean(true)
		}
		b.AddASN1OctetString(e.Value)
	})
}

// ParseRequest parses a DER OCSP request. Signed requests are rejected.
func ParseRequest(der []byte) (*Request, error) {
	in := cryptobyte.String(der)
	var outer, tbs, list cryptobyte.String
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) || !in.Empty() ||
		!outer.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, errors.New("ocsp: malformed request")
	}
	if !outer.Empty() {
		return nil, errors.New("ocsp: signed requests are not supported")
	}
	var version int64
	if !tbs.ReadOptionalASN1Integer(&version, cbasn1.Tag(0).Constructed().ContextSpecific(), int64(0)) || version != 0 {
		return nil, errors.New("ocsp: malformed or unsupported request version")
	}
	if !tbs.SkipOptionalASN1(cbasn1.Tag(1).Constructed().ContextSpecific()) || // requestorName
		!tbs.ReadASN1(&list, cbasn1.SEQUENCE) {
		return nil, errors.New("ocsp: malformed request")
	}
	r := new(Request)
	for !list.Empty() {
		var req cryptobyte.String
		if !list.ReadASN1(&req, cbasn1.SEQUENCE) {
			return nil, errors.New("ocsp: malformed request")
		}
		id, err := parseCertID(&req)
		if err != nil {
			return nil, err
		}
		if !req.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) || !req.Empty() {
			return nil, errors.New("ocsp: malformed request")
		}
		r.CertIDs = append(r.CertIDs, id)
	}
	if len(r.CertIDs) == 0 {
		return nil, errors.New("ocsp: request without certificates")
	}
	var err error
	if r.Extensions, err = readExtensions(&tbs, 2); err != nil {
		return nil, err
	}
	if !tbs.Empty() {
		return nil, errors.New("ocsp: trailing data in request")
	}
	return r, nil
}
