// Package x509util adds Brainpool keys to the X.509 and PKCS formats of
// crypto/x509: SubjectPublicKeyInfo, PKCS #8 and SEC 1 keys, and
// signature checks of certificates and CRLs with Brainpool keys.
//
// Keys on other curves and of other types go through crypto/x509, so the
// functions here can replace their crypto/x509 counterparts.
//
// The functions that take DER work with any Go release. Parsing a
// certificate with a Brainpool key into an *x509.Certificate needs a
// crypto/x509 that accepts keys on unsupported named curves (the ivory
// overlay); such certificates have a nil PublicKey, and PublicKey parses
// their key from RawSubjectPublicKeyInfo.
//
// Only named curves are supported (RFC 5480); explicit curve parameters
// are rejected, as is any point encoding other than uncompressed.
package x509util

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/DominicBreuker/ivory/brainpool"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Object identifiers of the Brainpool curves (RFC 5639, Section 4.1).
var (
	OIDBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	OIDBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	OIDBrainpoolP512r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}
)

// oidPublicKeyECDSA is id-ecPublicKey (RFC 5480, Section 2.1.1).
var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// CurveForOID returns the Brainpool curve with the namedCurve OID oid, or
// nil.
func CurveForOID(oid asn1.ObjectIdentifier) brainpool.Curve {
	switch {
	case oid.Equal(OIDBrainpoolP256r1):
		return brainpool.P256r1()
	case oid.Equal(OIDBrainpoolP384r1):
		return brainpool.P384r1()
	case oid.Equal(OIDBrainpoolP512r1):
		return brainpool.P512r1()
	}
	return nil
}

// OIDForCurve returns the namedCurve OID of c.
func OIDForCurve(c brainpool.Curve) asn1.ObjectIdentifier {
	switch c {
	case brainpool.P256r1():
		return OIDBrainpoolP256r1
	case brainpool.P384r1():
		return OIDBrainpoolP384r1
	case brainpool.P512r1():
		return OIDBrainpoolP512r1
	}
	panic("x509util: unknown curve")
}

// brainpoolCurve returns the curve that an id-ecPublicKey
// AlgorithmIdentifier's DER parameters name, or nil if the algorithm is
// not id-ecPublicKey with a Brainpool namedCurve. Parameters of any other
// form are left to crypto/x509.
func brainpoolCurve(algo asn1.ObjectIdentifier, params cryptobyte.String) brainpool.Curve {
	if !algo.Equal(oidPublicKeyECDSA) {
		return nil
	}
	var oid asn1.ObjectIdentifier
	if !params.ReadASN1ObjectIdentifier(&oid) || !params.Empty() {
		return nil
	}
	return CurveForOID(oid)
}

// readAlgorithmIdentifier reads an AlgorithmIdentifier and returns its OID
// and the raw parameters, empty if absent.
func readAlgorithmIdentifier(s *cryptobyte.String) (asn1.ObjectIdentifier, cryptobyte.String, bool) {
	var ai, params cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&ai, cbasn1.SEQUENCE) || !ai.ReadASN1ObjectIdentifier(&oid) {
		return nil, nil, false
	}
	if !ai.Empty() {
		var tag cbasn1.Tag
		if !ai.ReadAnyASN1Element(&params, &tag) || !ai.Empty() {
			return nil, nil, false
		}
	}
	return oid, params, true
}

// ParsePKIXPublicKey parses a DER SubjectPublicKeyInfo (RFC 5280, Section
// 4.1). A Brainpool key is returned as a *brainpool.PublicKey; any other
// key as crypto/x509.ParsePKIXPublicKey returns it.
func ParsePKIXPublicKey(der []byte) (any, error) {
	input := cryptobyte.String(der)
	var spki cryptobyte.String
	var bits asn1.BitString
	if !input.ReadASN1(&spki, cbasn1.SEQUENCE) || !input.Empty() {
		return x509.ParsePKIXPublicKey(der)
	}
	oid, params, ok := readAlgorithmIdentifier(&spki)
	if !ok {
		return x509.ParsePKIXPublicKey(der)
	}
	c := brainpoolCurve(oid, params)
	if c == nil {
		return x509.ParsePKIXPublicKey(der)
	}
	if !spki.ReadASN1BitString(&bits) || !spki.Empty() || bits.BitLength%8 != 0 {
		return nil, errors.New("x509util: malformed Brainpool public key")
	}
	pub, err := brainpool.NewPublicKey(c, bits.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509util: invalid %v public key: %w", c, err)
	}
	return pub, nil
}

// MarshalPKIXPublicKey returns the DER SubjectPublicKeyInfo of pub, with a
// namedCurve parameter and the uncompressed point.
func MarshalPKIXPublicKey(pub *brainpool.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("x509util: nil public key")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addECAlgorithmIdentifier(b, pub.Curve())
		b.AddASN1BitString(pub.Bytes())
	})
	return b.Bytes()
}

func addECAlgorithmIdentifier(b *cryptobyte.Builder, c brainpool.Curve) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidPublicKeyECDSA)
		b.AddASN1ObjectIdentifier(OIDForCurve(c))
	})
}

// ParsePKCS8PrivateKey parses a DER PKCS #8 PrivateKeyInfo (RFC 5208,
// RFC 5958). A Brainpool key is returned as a *brainpool.PrivateKey; any
// other key as crypto/x509.ParsePKCS8PrivateKey returns it.
func ParsePKCS8PrivateKey(der []byte) (any, error) {
	input := cryptobyte.String(der)
	var pki, inner cryptobyte.String
	var version int64
	if !input.ReadASN1(&pki, cbasn1.SEQUENCE) || !input.Empty() ||
		!pki.ReadASN1Integer(&version) {
		return x509.ParsePKCS8PrivateKey(der)
	}
	oid, params, ok := readAlgorithmIdentifier(&pki)
	if !ok {
		return x509.ParsePKCS8PrivateKey(der)
	}
	c := brainpoolCurve(oid, params)
	if c == nil {
		return x509.ParsePKCS8PrivateKey(der)
	}
	if version != 0 && version != 1 || !pki.ReadASN1(&inner, cbasn1.OCTET_STRING) {
		return nil, errors.New("x509util: malformed PKCS #8 Brainpool key")
	}
	// Optional attributes [0] and, in version 1 (RFC 5958), publicKey [1].
	// The public key is checked against the private key below.
	var pkcs8Pub cryptobyte.String
	var hasPub bool
	if !pki.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!pki.ReadOptionalASN1(&pkcs8Pub, &hasPub, cbasn1.Tag(1).ContextSpecific()) ||
		!pki.Empty() || hasPub && version != 1 {
		return nil, errors.New("x509util: malformed PKCS #8 Brainpool key")
	}
	k, err := parseECPrivateKey(c, inner)
	if err != nil {
		return nil, err
	}
	if hasPub {
		// [1] IMPLICIT BIT STRING: unused-bits byte, then the point.
		if len(pkcs8Pub) < 1 || pkcs8Pub[0] != 0 || !bytes.Equal(pkcs8Pub[1:], k.PublicKey().Bytes()) {
			return nil, errors.New("x509util: PKCS #8 public key doesn't match the private key")
		}
	}
	return k, nil
}

// MarshalPKCS8PrivateKey returns the DER PKCS #8 PrivateKeyInfo of k, in
// the form OpenSSL and crypto/x509 write: version 0, id-ecPublicKey with a
// namedCurve parameter, and a SEC 1 ECPrivateKey with the public key and
// without parameters.
func MarshalPKCS8PrivateKey(k *brainpool.PrivateKey) ([]byte, error) {
	if k == nil {
		return nil, errors.New("x509util: nil private key")
	}
	inner, err := marshalECPrivateKey(k, false)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		addECAlgorithmIdentifier(b, k.Curve())
		b.AddASN1OctetString(inner)
	})
	return b.Bytes()
}

// ParseECPrivateKey parses a DER SEC 1 ECPrivateKey (RFC 5915) on a
// Brainpool curve. The parameters must name the curve, the "named-curve"
// encoding of A_23511 (gemSpec_Krypt V2.51.0); explicit parameters and keys
// on other curves are errors. A public key in the structure must match the
// private key.
func ParseECPrivateKey(der []byte) (*brainpool.PrivateKey, error) {
	return parseECPrivateKey(nil, der)
}

// parseECPrivateKey parses a SEC 1 key. If c is not nil, it comes from the
// PKCS #8 wrapper, and the key's own parameters may be absent.
func parseECPrivateKey(c brainpool.Curve, der []byte) (*brainpool.PrivateKey, error) {
	input := cryptobyte.String(der)
	var s, d, params, pubBits cryptobyte.String
	var version int64
	var hasParams, hasPub bool
	if !input.ReadASN1(&s, cbasn1.SEQUENCE) || !input.Empty() ||
		!s.ReadASN1Integer(&version) || version != 1 ||
		!s.ReadASN1(&d, cbasn1.OCTET_STRING) ||
		!s.ReadOptionalASN1(&params, &hasParams, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!s.ReadOptionalASN1(&pubBits, &hasPub, cbasn1.Tag(1).Constructed().ContextSpecific()) ||
		!s.Empty() {
		return nil, errors.New("x509util: malformed EC private key")
	}
	if hasParams {
		var oid asn1.ObjectIdentifier
		if !params.ReadASN1ObjectIdentifier(&oid) || !params.Empty() {
			return nil, errors.New("x509util: EC private key parameters are not a named curve")
		}
		kc := CurveForOID(oid)
		if kc == nil {
			return nil, fmt.Errorf("x509util: EC private key on curve %v is not a Brainpool key", oid)
		}
		if c != nil && kc != c {
			return nil, errors.New("x509util: EC private key curve doesn't match the PKCS #8 algorithm")
		}
		c = kc
	}
	if c == nil {
		return nil, errors.New("x509util: EC private key without a named curve")
	}
	// Like crypto/x509, accept a scalar with leading zeros removed or
	// added, which SEC 1 doesn't allow but older encoders produce.
	size := brainpool.Size(c)
	for len(d) > size && d[0] == 0 {
		d = d[1:]
	}
	if len(d) > size {
		return nil, errors.New("x509util: invalid EC private key length")
	}
	scalar := make([]byte, size)
	copy(scalar[size-len(d):], d)
	k, err := brainpool.NewPrivateKey(c, scalar)
	if err != nil {
		return nil, fmt.Errorf("x509util: invalid %v private key: %w", c, err)
	}
	if hasPub {
		var bits asn1.BitString
		if !pubBits.ReadASN1BitString(&bits) || !pubBits.Empty() || bits.BitLength%8 != 0 ||
			!bytes.Equal(bits.Bytes, k.PublicKey().Bytes()) {
			return nil, errors.New("x509util: EC public key doesn't match the private key")
		}
	}
	return k, nil
}

// MarshalECPrivateKey returns the DER SEC 1 ECPrivateKey of k (RFC 5915),
// with the namedCurve parameter and the public key, as OpenSSL writes it.
func MarshalECPrivateKey(k *brainpool.PrivateKey) ([]byte, error) {
	if k == nil {
		return nil, errors.New("x509util: nil private key")
	}
	return marshalECPrivateKey(k, true)
}

func marshalECPrivateKey(k *brainpool.PrivateKey, withParams bool) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1OctetString(k.Bytes())
		if withParams {
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(OIDForCurve(k.Curve()))
			})
		}
		b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1BitString(k.PublicKey().Bytes())
		})
	})
	return b.Bytes()
}

// PublicKey returns cert's public key: cert.PublicKey if crypto/x509
// parsed it, otherwise the result of ParsePKIXPublicKey on
// RawSubjectPublicKeyInfo, a *brainpool.PublicKey for a Brainpool key.
func PublicKey(cert *x509.Certificate) (any, error) {
	if cert.PublicKey != nil {
		return cert.PublicKey, nil
	}
	return ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
}

// CheckSignature checks that signature is a valid signature over signed by
// pub, with the algorithm algo.
//
// For a *brainpool.PublicKey, algo must be x509.ECDSAWithSHA256,
// ECDSAWithSHA384 or ECDSAWithSHA512 (Tab_KRYPT_002a of GS-A_4357-02,
// gemSpec_Krypt V2.51.0), with any of the three curves, and the signature
// must be strict DER. Other keys go to crypto/x509.
//
// Unlike x509.Certificate.CheckSignature, signatures with SHA-1 are
// rejected for every key type with an x509.InsecureAlgorithmError.
func CheckSignature(algo x509.SignatureAlgorithm, signed, signature []byte, pub any) error {
	switch algo {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
		return x509.InsecureAlgorithmError(algo)
	}
	bp, ok := pub.(*brainpool.PublicKey)
	if !ok {
		return (&x509.Certificate{PublicKey: pub}).CheckSignature(algo, signed, signature)
	}
	var h crypto.Hash
	switch algo {
	case x509.ECDSAWithSHA256:
		h = crypto.SHA256
	case x509.ECDSAWithSHA384:
		h = crypto.SHA384
	case x509.ECDSAWithSHA512:
		h = crypto.SHA512
	default:
		return fmt.Errorf("x509util: signature algorithm %v is not allowed for Brainpool keys: %w", algo, x509.ErrUnsupportedAlgorithm)
	}
	hh := h.New()
	hh.Write(signed)
	if !brainpool.VerifyASN1(bp, hh.Sum(nil), signature) {
		return errors.New("x509util: ECDSA verification failure")
	}
	return nil
}

// CheckCertificateSignatureFrom checks that child's signature is valid
// under parent's key, from child's RawTBSCertificate, Signature and
// SignatureAlgorithm (TUC_PKI_004, gemSpec_PKI V2.28.0). parent's key may
// be a Brainpool key.
//
// Like x509.Certificate.CheckSignatureFrom, it requires parent to be a CA
// (basicConstraints cA, or a version 1 or 2 certificate) whose keyUsage,
// if present, allows keyCertSign; otherwise it returns an
// x509.ConstraintViolationError. For a parent whose key crypto/x509
// supports, it is x509.Certificate.CheckSignatureFrom. It checks nothing
// else: no names, validity, path or revocation.
func CheckCertificateSignatureFrom(child, parent *x509.Certificate) error {
	if parent.PublicKey != nil {
		return child.CheckSignatureFrom(parent)
	}
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return x509.ConstraintViolationError{}
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}
	pub, err := PublicKey(parent)
	if err != nil {
		return err
	}
	return CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature, pub)
}

// CheckCRLSignatureFrom checks that crl's signature is valid under
// issuer's key, which may be a Brainpool key.
//
// Unlike x509.RevocationList.CheckSignatureFrom, issuer need not be a CA:
// CRL signers in the TI have cA = FALSE (profile C.GEM.CRL, gemSpec_PKI
// V2.28.0 GS-A_4939). issuer's keyUsage, if present, must allow cRLSign;
// otherwise CheckCRLSignatureFrom returns an x509.ConstraintViolationError.
// Signatures with SHA-1 are rejected (see CheckSignature). It checks
// nothing else: not that issuer is the CRL's issuer or is entitled to sign
// it, and no times.
func CheckCRLSignatureFrom(crl *x509.RevocationList, issuer *x509.Certificate) error {
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return x509.ConstraintViolationError{}
	}
	pub, err := PublicKey(issuer)
	if err != nil {
		return err
	}
	return CheckSignature(crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature, pub)
}
