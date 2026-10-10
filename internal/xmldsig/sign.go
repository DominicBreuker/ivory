package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/DominicBreuker/ivory/brainpool"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SignEnveloped adds an enveloped signature to the XML document unsigned,
// as the last child of its root element, made with key, the key of
// signer, the way the TI's TSL service signs: exclusive canonicalization,
// SHA-256, ECDSA (Brainpool or NIST, r || s) or RSA PKCS #1 v1.5, a
// reference to the whole document and one to XAdES signed properties.
//
// It is meant for tests: test TSLs and simulators. Signing TSLs is the
// TSL service's job, not a TI product's.
func SignEnveloped(unsigned []byte, signer *x509.Certificate, key crypto.Signer) ([]byte, error) {
	sigAlg := algECDSA256
	if _, ok := key.(*rsa.PrivateKey); ok {
		sigAlg = algRSA256
	}
	sigTmpl := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="signature-ivory"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + algExcC14N + `"/>` +
		`<ds:SignatureMethod Algorithm="` + sigAlg + `"/>` +
		`<ds:Reference Id="reference-document" URI=""><ds:Transforms>` +
		`<ds:Transform Algorithm="` + algEnveloped + `"/>` +
		`<ds:Transform Algorithm="` + algExcC14N + `"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + algSHA256 + `"/><ds:DigestValue>DOC</ds:DigestValue></ds:Reference>` +
		`<ds:Reference Type="` + typeSignedPro + `" URI="#signedproperties-ivory"><ds:Transforms>` +
		`<ds:Transform Algorithm="` + algExcC14N + `"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + algSHA256 + `"/><ds:DigestValue>PROPS</ds:DigestValue></ds:Reference>` +
		`</ds:SignedInfo><ds:SignatureValue>SIG</ds:SignatureValue>` +
		`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(signer.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
		`<ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#signature-ivory">` +
		`<xades:SignedProperties Id="signedproperties-ivory"><xades:SignedSignatureProperties><xades:SigningTime>2030-01-01T00:00:00Z</xades:SigningTime>` +
		`</xades:SignedSignatureProperties></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature>`
	doc0, err := Parse(unsigned)
	if err != nil {
		return nil, err
	}
	end := "</" + doc0.Root.Name() + ">"
	i := strings.LastIndex(string(unsigned), end)
	if i < 0 {
		return nil, errors.New("xmldsig: no end tag of the root element")
	}
	assemble := func(s string) []byte { return []byte(string(unsigned[:i]) + s + string(unsigned[i:])) }

	doc, err := Parse(assemble(sigTmpl))
	if err != nil {
		return nil, err
	}
	sig := doc.IDs["signature-ivory"]
	docDigest := sha256.Sum256(CanonicalizeDocument(doc, sig))
	propsDigest := sha256.Sum256(CanonicalizeSubtree(doc.IDs["signedproperties-ivory"], nil))
	sigTmpl = strings.Replace(sigTmpl, "DOC", base64.StdEncoding.EncodeToString(docDigest[:]), 1)
	sigTmpl = strings.Replace(sigTmpl, "PROPS", base64.StdEncoding.EncodeToString(propsDigest[:]), 1)

	if doc, err = Parse(assemble(sigTmpl)); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(CanonicalizeSubtree(doc.IDs["signature-ivory"].Children()[0], nil))
	var value []byte
	switch k := key.(type) {
	case *brainpool.PrivateKey:
		value, err = brainpool.SignRaw(rand.Reader, k, digest[:])
	case *ecdsa.PrivateKey:
		var der []byte
		if der, err = ecdsa.SignASN1(rand.Reader, k, digest[:]); err == nil {
			value, err = rawECDSA(der, (k.Curve.Params().BitSize+7)/8)
		}
	case *rsa.PrivateKey:
		value, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	default:
		err = fmt.Errorf("xmldsig: unsupported key %T", key)
	}
	if err != nil {
		return nil, err
	}
	return assemble(strings.Replace(sigTmpl, "SIG", base64.StdEncoding.EncodeToString(value), 1)), nil
}

// rawECDSA converts a DER ECDSA signature into r || s with size bytes
// each.
func rawECDSA(der []byte, size int) ([]byte, error) {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	var r, s []byte
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Integer(&r) || !seq.ReadASN1Integer(&s) {
		return nil, errors.New("xmldsig: malformed ECDSA signature")
	}
	out := make([]byte, 2*size)
	r, s = bytes.TrimLeft(r, "\x00"), bytes.TrimLeft(s, "\x00")
	if len(r) > size || len(s) > size {
		return nil, errors.New("xmldsig: malformed ECDSA signature")
	}
	copy(out[size-len(r):size], r)
	copy(out[2*size-len(s):], s)
	return out, nil
}
