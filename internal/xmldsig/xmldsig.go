package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/DominicBreuker/ivory/x509util"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// XML Signature (XMLDSig) verification for the enveloped signature of a
// TSL (ETSI TS 102 231 V3.1.2, Section 5.7 and Annex B; gemSpec_PKI
// TUC_PKI_012), in the forms the TSL service uses: exclusive
// canonicalization, one reference to the whole document with the
// enveloped-signature transform, and same-document references to XAdES
// properties inside the signature.

const (
	NSDSig = "http://www.w3.org/2000/09/xmldsig#"

	algExcC14N    = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algEnveloped  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algSHA256     = "http://www.w3.org/2001/04/xmlenc#sha256"
	algSHA384     = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	algSHA512     = "http://www.w3.org/2001/04/xmlenc#sha512"
	algECDSA256   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	algECDSA384   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	algECDSA512   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	algRSA256     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algRSA384     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	algRSA512     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	algRSAPSS256  = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	algRSAPSS384  = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1"
	algRSAPSS512  = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"
	typeSignedPro = "http://uri.etsi.org/01903#SignedProperties"
)

var digestAlgs = map[string]crypto.Hash{
	algSHA256: crypto.SHA256,
	algSHA384: crypto.SHA384,
	algSHA512: crypto.SHA512,
}

var signatureAlgs = map[string]x509.SignatureAlgorithm{
	algECDSA256:  x509.ECDSAWithSHA256,
	algECDSA384:  x509.ECDSAWithSHA384,
	algECDSA512:  x509.ECDSAWithSHA512,
	algRSA256:    x509.SHA256WithRSA,
	algRSA384:    x509.SHA384WithRSA,
	algRSA512:    x509.SHA512WithRSA,
	algRSAPSS256: x509.SHA256WithRSAPSS,
	algRSAPSS384: x509.SHA384WithRSAPSS,
	algRSAPSS512: x509.SHA512WithRSAPSS,
}

// ErrSignature is wrapped by the errors of signature verification
// (XML_SIGNATURE_ERROR of TUC_PKI_012).
var ErrSignature = errors.New("XML_SIGNATURE_ERROR")

func sigErr(format string, args ...any) error {
	return fmt.Errorf("tsl: %s: %w", fmt.Sprintf(format, args...), ErrSignature)
}

// A Signature is the parsed enveloped signature of a document.
type Signature struct {
	Elem       *Element
	SignedInfo *Element
	Algorithm  x509.SignatureAlgorithm
	Value      []byte
	// Certs are the DER certificates of KeyInfo/X509Data.
	Certs [][]byte
}

// FindSignature returns the ds:Signature child of the root element. A
// document with more than one such child is rejected.
func FindSignature(doc *Document) (*Signature, error) {
	var sigs []*Element
	for _, c := range doc.Root.Children() {
		if c.Is(NSDSig, "Signature") {
			sigs = append(sigs, c)
		}
	}
	switch len(sigs) {
	case 0:
		return nil, sigErr("no signature")
	case 1:
	default:
		return nil, sigErr("more than one signature")
	}
	s := &Signature{Elem: sigs[0]}
	kids := s.Elem.Children()
	if len(kids) < 2 || !kids[0].Is(NSDSig, "SignedInfo") || !kids[1].Is(NSDSig, "SignatureValue") {
		return nil, sigErr("malformed Signature element")
	}
	s.SignedInfo = kids[0]
	var err error
	if s.Value, err = DecodeBase64(kids[1].Text()); err != nil {
		return nil, sigErr("malformed SignatureValue")
	}
	if len(kids) > 2 && kids[2].Is(NSDSig, "KeyInfo") {
		for _, d := range kids[2].Children() {
			if !d.Is(NSDSig, "X509Data") {
				continue
			}
			for _, c := range d.Children() {
				if c.Is(NSDSig, "X509Certificate") {
					der, err := DecodeBase64(c.Text())
					if err != nil {
						return nil, sigErr("malformed X509Certificate")
					}
					s.Certs = append(s.Certs, der)
				}
			}
		}
	}
	si := s.SignedInfo.Children()
	if len(si) < 3 || !si[0].Is(NSDSig, "CanonicalizationMethod") || !si[1].Is(NSDSig, "SignatureMethod") {
		return nil, sigErr("malformed SignedInfo")
	}
	if alg, _ := si[0].Attr("Algorithm"); alg != algExcC14N || len(si[0].Children()) != 0 {
		return nil, sigErr("unsupported canonicalization %q", alg)
	}
	alg, _ := si[1].Attr("Algorithm")
	var ok bool
	if s.Algorithm, ok = signatureAlgs[alg]; !ok || len(si[1].Children()) != 0 {
		return nil, sigErr("unsupported signature algorithm %q", alg)
	}
	return s, nil
}

func DecodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.Strict().DecodeString(s)
}

// VerifyReferences checks the digests of all references of s. Exactly one
// reference must cover the whole document (URI="" with the
// enveloped-signature transform); the others may only point to elements
// inside the signature (XAdES signed properties).
func (s *Signature) VerifyReferences(doc *Document) error {
	whole := 0
	refs := s.SignedInfo.Children()[2:]
	for _, ref := range refs {
		if !ref.Is(NSDSig, "Reference") {
			return sigErr("unexpected element %s in SignedInfo", ref.Name())
		}
		uri, ok := ref.Attr("URI")
		if !ok {
			return sigErr("reference without URI")
		}
		var transforms []string
		kids := ref.Children()
		if len(kids) > 0 && kids[0].Is(NSDSig, "Transforms") {
			for _, tr := range kids[0].Children() {
				alg, _ := tr.Attr("Algorithm")
				if !tr.Is(NSDSig, "Transform") || len(tr.Children()) != 0 {
					return sigErr("unsupported transform")
				}
				transforms = append(transforms, alg)
			}
			kids = kids[1:]
		}
		if len(kids) != 2 || !kids[0].Is(NSDSig, "DigestMethod") || !kids[1].Is(NSDSig, "DigestValue") {
			return sigErr("malformed reference %q", uri)
		}
		alg, _ := kids[0].Attr("Algorithm")
		h, ok := digestAlgs[alg]
		if !ok {
			return sigErr("unsupported digest algorithm %q", alg)
		}
		want, err := DecodeBase64(kids[1].Text())
		if err != nil {
			return sigErr("malformed DigestValue")
		}
		var data []byte
		switch {
		case uri == "":
			if !equalStrings(transforms, algEnveloped, algExcC14N) {
				return sigErr("unsupported transforms %q for the document", transforms)
			}
			whole++
			data = CanonicalizeDocument(doc, s.Elem)
		case strings.HasPrefix(uri, "#"):
			if !equalStrings(transforms, algExcC14N) {
				return sigErr("unsupported transforms %q for %q", transforms, uri)
			}
			target := doc.IDs[uri[1:]]
			if target == nil || !inside(target, s.Elem) {
				return sigErr("reference %q doesn't point into the signature", uri)
			}
			data = CanonicalizeSubtree(target, nil)
		default:
			return sigErr("unsupported reference URI %q", uri)
		}
		hh := h.New()
		hh.Write(data)
		if subtle.ConstantTimeCompare(hh.Sum(nil), want) != 1 {
			return sigErr("digest of reference %q doesn't match", uri)
		}
	}
	if whole != 1 {
		return sigErr("need exactly one reference to the whole document, have %d", whole)
	}
	return nil
}

func equalStrings(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// inside reports whether e is anc or a descendant of anc.
func inside(e, anc *Element) bool {
	for ; e != nil; e = e.Parent {
		if e == anc {
			return true
		}
	}
	return false
}

// VerifyValue checks the signature over the canonical SignedInfo
// with signer's key.
func (s *Signature) VerifyValue(signer *x509.Certificate) error {
	pub, err := x509util.PublicKey(signer)
	if err != nil {
		return sigErr("signer key: %v", err)
	}
	sig := s.Value
	switch s.Algorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		// XMLDSig carries r || s (RFC 6931, Section 2.3.6); x509util
		// takes DER.
		if sig, err = ecdsaDER(sig); err != nil {
			return sigErr("%v", err)
		}
	}
	signed := CanonicalizeSubtree(s.SignedInfo, nil)
	if err := x509util.CheckSignature(s.Algorithm, signed, sig, pub); err != nil {
		return sigErr("%v", err)
	}
	return nil
}

func ecdsaDER(rs []byte) ([]byte, error) {
	if len(rs) == 0 || len(rs)%2 != 0 || len(rs) > 2*66 {
		return nil, errors.New("malformed ECDSA signature value")
	}
	n := len(rs) / 2
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addUnsigned(b, rs[:n])
		addUnsigned(b, rs[n:])
	})
	return b.Bytes()
}

// addUnsigned adds the big-endian unsigned integer v as an ASN.1 INTEGER.
func addUnsigned(b *cryptobyte.Builder, v []byte) {
	v = bytes.TrimLeft(v, "\x00")
	b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) {
		if len(v) == 0 || v[0]&0x80 != 0 {
			b.AddUint8(0)
		}
		b.AddBytes(v)
	})
}
