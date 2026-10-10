package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/DominicBreuker/ivory/x509util"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// A ResponseStatus is the responseStatus of an OCSP response (RFC 6960,
// Section 4.2.1).
type ResponseStatus int

// Response statuses. 4 is not used.
const (
	Successful       ResponseStatus = 0
	MalformedRequest ResponseStatus = 1
	InternalError    ResponseStatus = 2
	TryLater         ResponseStatus = 3
	SigRequired      ResponseStatus = 5
	Unauthorized     ResponseStatus = 6
)

func (s ResponseStatus) String() string {
	switch s {
	case Successful:
		return "successful"
	case MalformedRequest:
		return "malformedRequest"
	case InternalError:
		return "internalError"
	case TryLater:
		return "tryLater"
	case SigRequired:
		return "sigRequired"
	case Unauthorized:
		return "unauthorized"
	}
	return "status(" + strconv.Itoa(int(s)) + ")"
}

// A CertStatus is the status of one certificate in a response.
type CertStatus int

// Certificate statuses (RFC 6960, Section 4.2.1).
const (
	Good CertStatus = iota
	Revoked
	Unknown
)

func (s CertStatus) String() string {
	switch s {
	case Good:
		return "good"
	case Revoked:
		return "revoked"
	case Unknown:
		return "unknown"
	}
	return "CertStatus(" + strconv.Itoa(int(s)) + ")"
}

// Object identifiers used by this package.
var (
	// OIDCertHash is the certHash extension of Common PKI
	// (id-isismtt-at-certHash), which TI responders put into every good
	// single response (GS-A_4693-01).
	OIDCertHash = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 13}
	// OIDNonce is the nonce extension (RFC 6960, Section 4.4.1).
	OIDNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

	oidBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

func hashForOID(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1
	case oid.Equal(oidSHA256):
		return crypto.SHA256
	case oid.Equal(oidSHA384):
		return crypto.SHA384
	case oid.Equal(oidSHA512):
		return crypto.SHA512
	}
	return 0
}

func oidForHash(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA1:
		return oidSHA1
	case crypto.SHA256:
		return oidSHA256
	case crypto.SHA384:
		return oidSHA384
	case crypto.SHA512:
		return oidSHA512
	}
	return nil
}

// A CertID identifies a certificate in requests and responses (RFC 6960,
// Section 4.1.1).
type CertID struct {
	// HashAlgorithm is the hash of IssuerNameHash and IssuerKeyHash:
	// crypto.SHA1, SHA256, SHA384 or SHA512.
	HashAlgorithm crypto.Hash
	// HashParametersNull says whether the AlgorithmIdentifier carries
	// NULL parameters. Both forms are valid (gemSpec_PKI Tab_PKI_290);
	// they don't affect matching.
	HashParametersNull bool

	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// NewCertID returns the CertID of cert, issued by issuer, with hash h.
// issuer's key may be a Brainpool key: only its encoded form is hashed.
func NewCertID(cert, issuer *x509.Certificate, h crypto.Hash) (*CertID, error) {
	if oidForHash(h) == nil || !h.Available() {
		return nil, fmt.Errorf("ocsp: unsupported CertID hash %v", h)
	}
	nameHash, keyHash, err := issuerHashes(issuer, h)
	if err != nil {
		return nil, err
	}
	return &CertID{
		HashAlgorithm:      h,
		HashParametersNull: true,
		IssuerNameHash:     nameHash,
		IssuerKeyHash:      keyHash,
		SerialNumber:       new(big.Int).Set(cert.SerialNumber),
	}, nil
}

// issuerHashes returns the hashes of issuer's subject and of the value of
// the BIT STRING subjectPublicKey of its key.
func issuerHashes(issuer *x509.Certificate, h crypto.Hash) (nameHash, keyHash []byte, err error) {
	spki := cryptobyte.String(issuer.RawSubjectPublicKeyInfo)
	var inner cryptobyte.String
	var key asn1.BitString
	if !spki.ReadASN1(&inner, cbasn1.SEQUENCE) || !inner.SkipASN1(cbasn1.SEQUENCE) ||
		!inner.ReadASN1BitString(&key) || !inner.Empty() || !spki.Empty() {
		return nil, nil, errors.New("ocsp: malformed issuer public key")
	}
	hh := h.New()
	hh.Write(issuer.RawSubject)
	nameHash = hh.Sum(nil)
	hh.Reset()
	hh.Write(key.Bytes)
	return nameHash, hh.Sum(nil), nil
}

// Matches reports whether id identifies cert, issued by issuer, using the
// hash algorithm of id. The parameters of the AlgorithmIdentifier (NULL or
// absent) don't matter.
func (id *CertID) Matches(cert, issuer *x509.Certificate) bool {
	if id == nil || id.SerialNumber == nil || cert.SerialNumber == nil ||
		oidForHash(id.HashAlgorithm) == nil || !id.HashAlgorithm.Available() {
		return false
	}
	nameHash, keyHash, err := issuerHashes(issuer, id.HashAlgorithm)
	if err != nil {
		return false
	}
	return id.SerialNumber.Cmp(cert.SerialNumber) == 0 &&
		bytes.Equal(id.IssuerNameHash, nameHash) && bytes.Equal(id.IssuerKeyHash, keyHash)
}

func (id *CertID) marshal(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidForHash(id.HashAlgorithm))
			if id.HashParametersNull {
				b.AddASN1NULL()
			}
		})
		b.AddASN1OctetString(id.IssuerNameHash)
		b.AddASN1OctetString(id.IssuerKeyHash)
		b.AddASN1BigInt(id.SerialNumber)
	})
}

func parseCertID(s *cryptobyte.String) (*CertID, error) {
	var seq, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	id := &CertID{SerialNumber: new(big.Int)}
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1ObjectIdentifier(&oid) {
		return nil, errors.New("ocsp: malformed CertID")
	}
	if alg.PeekASN1Tag(cbasn1.NULL) {
		id.HashParametersNull = true
		var null cryptobyte.String
		if !alg.ReadASN1(&null, cbasn1.NULL) || !null.Empty() {
			return nil, errors.New("ocsp: malformed CertID hash parameters")
		}
	}
	if !alg.Empty() {
		return nil, errors.New("ocsp: malformed CertID hash parameters")
	}
	id.HashAlgorithm = hashForOID(oid)
	if id.HashAlgorithm == 0 {
		return nil, fmt.Errorf("ocsp: unsupported CertID hash algorithm %v", oid)
	}
	if !seq.ReadASN1Bytes(&id.IssuerNameHash, cbasn1.OCTET_STRING) ||
		!seq.ReadASN1Bytes(&id.IssuerKeyHash, cbasn1.OCTET_STRING) ||
		!seq.ReadASN1Integer(id.SerialNumber) || !seq.Empty() {
		return nil, errors.New("ocsp: malformed CertID")
	}
	return id, nil
}

// A Response is a parsed OCSP response.
type Response struct {
	// Raw is the complete DER response.
	Raw []byte

	// Status is the responseStatus. The other fields are set only if it
	// is Successful.
	Status ResponseStatus

	// TBSResponseData is the signed part, ResponseData.
	TBSResponseData []byte
	// SignatureAlgorithm is the signature algorithm, or
	// x509.UnknownSignatureAlgorithm.
	SignatureAlgorithm x509.SignatureAlgorithm
	// RawSignatureAlgorithm is the DER AlgorithmIdentifier of the
	// signature.
	RawSignatureAlgorithm []byte
	Signature             []byte

	// Exactly one of ResponderName and ResponderKeyHash is set:
	// ResponderName is the DER Name of the responder ID byName,
	// ResponderKeyHash the SHA-1 hash of the responder's public key
	// (byKey).
	ResponderName    []byte
	ResponderKeyHash []byte

	ProducedAt time.Time
	Responses  []SingleResponse
	// Extensions are the responseExtensions.
	Extensions []pkix.Extension

	// Certificates are the DER certificates the responder sent along.
	// They are not trusted; Verify ignores them.
	Certificates [][]byte
}

// A SingleResponse is the status of one certificate.
type SingleResponse struct {
	CertID *CertID
	Status CertStatus

	// RevokedAt and RevocationReason are set if Status is Revoked.
	// RevocationReason is -1 if the response gives no reason.
	RevokedAt        time.Time
	RevocationReason int

	ThisUpdate time.Time
	// NextUpdate is the zero time if the response has none.
	NextUpdate time.Time

	// Extensions are the singleExtensions.
	Extensions []pkix.Extension
	// CertHash is the parsed certHash extension, or nil.
	CertHash *CertHash
}

// A CertHash is the value of the certHash extension: a hash over the DER
// certificate.
type CertHash struct {
	HashAlgorithm crypto.Hash
	Hash          []byte
}

// ParseResponse parses a DER OCSP response. It checks the structure only:
// no signature, no times, no status. A response whose responseStatus is
// not Successful parses without error; its Status says so.
func ParseResponse(der []byte) (*Response, error) {
	r := &Response{Raw: der}
	in := cryptobyte.String(der)
	var outer cryptobyte.String
	var status int
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) || !in.Empty() ||
		!outer.ReadASN1Enum(&status) {
		return nil, errors.New("ocsp: malformed response")
	}
	r.Status = ResponseStatus(status)
	var bytesField cryptobyte.String
	var hasBytes bool
	if !outer.ReadOptionalASN1(&bytesField, &hasBytes, cbasn1.Tag(0).Constructed().ContextSpecific()) || !outer.Empty() {
		return nil, errors.New("ocsp: malformed response")
	}
	if r.Status != Successful {
		return r, nil
	}
	if !hasBytes {
		return nil, errors.New("ocsp: successful response without responseBytes")
	}
	var rb cryptobyte.String
	var typ asn1.ObjectIdentifier
	var basic cryptobyte.String
	if !bytesField.ReadASN1(&rb, cbasn1.SEQUENCE) || !bytesField.Empty() ||
		!rb.ReadASN1ObjectIdentifier(&typ) || !rb.ReadASN1(&basic, cbasn1.OCTET_STRING) || !rb.Empty() {
		return nil, errors.New("ocsp: malformed responseBytes")
	}
	if !typ.Equal(oidBasicResponse) {
		return nil, fmt.Errorf("ocsp: unsupported response type %v", typ)
	}
	if err := r.parseBasic(basic); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Response) parseBasic(in cryptobyte.String) error {
	var seq, tbs, alg cryptobyte.String
	var sig asn1.BitString
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() ||
		!seq.ReadASN1Element(&tbs, cbasn1.SEQUENCE) ||
		!seq.ReadASN1Element(&alg, cbasn1.SEQUENCE) ||
		!seq.ReadASN1BitString(&sig) {
		return errors.New("ocsp: malformed BasicOCSPResponse")
	}
	if sig.BitLength%8 != 0 {
		return errors.New("ocsp: signature is not a whole number of bytes")
	}
	r.TBSResponseData = tbs
	r.RawSignatureAlgorithm = alg
	r.SignatureAlgorithm = signatureAlgorithm(alg)
	r.Signature = sig.Bytes
	var certs cryptobyte.String
	var hasCerts bool
	if !seq.ReadOptionalASN1(&certs, &hasCerts, cbasn1.Tag(0).Constructed().ContextSpecific()) || !seq.Empty() {
		return errors.New("ocsp: malformed BasicOCSPResponse")
	}
	if hasCerts {
		var list cryptobyte.String
		if !certs.ReadASN1(&list, cbasn1.SEQUENCE) || !certs.Empty() {
			return errors.New("ocsp: malformed certificate list")
		}
		for !list.Empty() {
			var c cryptobyte.String
			if !list.ReadASN1Element(&c, cbasn1.SEQUENCE) {
				return errors.New("ocsp: malformed certificate list")
			}
			r.Certificates = append(r.Certificates, c)
		}
	}
	return r.parseResponseData(tbs)
}

func (r *Response) parseResponseData(in cryptobyte.String) error {
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return errors.New("ocsp: malformed ResponseData")
	}
	var version int64
	if !seq.ReadOptionalASN1Integer(&version, cbasn1.Tag(0).Constructed().ContextSpecific(), int64(0)) || version != 0 {
		return errors.New("ocsp: malformed or unsupported ResponseData version")
	}
	switch {
	case seq.PeekASN1Tag(cbasn1.Tag(1).Constructed().ContextSpecific()):
		var name, n cryptobyte.String
		if !seq.ReadASN1(&name, cbasn1.Tag(1).Constructed().ContextSpecific()) ||
			!name.ReadASN1Element(&n, cbasn1.SEQUENCE) || !name.Empty() {
			return errors.New("ocsp: malformed responder name")
		}
		r.ResponderName = n
	case seq.PeekASN1Tag(cbasn1.Tag(2).Constructed().ContextSpecific()):
		var key cryptobyte.String
		if !seq.ReadASN1(&key, cbasn1.Tag(2).Constructed().ContextSpecific()) ||
			!key.ReadASN1Bytes(&r.ResponderKeyHash, cbasn1.OCTET_STRING) || !key.Empty() {
			return errors.New("ocsp: malformed responder key hash")
		}
	default:
		return errors.New("ocsp: malformed responder ID")
	}
	var err error
	if r.ProducedAt, err = readGeneralizedTime(&seq); err != nil {
		return fmt.Errorf("ocsp: producedAt: %w", err)
	}
	var list cryptobyte.String
	if !seq.ReadASN1(&list, cbasn1.SEQUENCE) {
		return errors.New("ocsp: malformed responses")
	}
	for !list.Empty() {
		sr, err := parseSingleResponse(&list)
		if err != nil {
			return err
		}
		r.Responses = append(r.Responses, *sr)
	}
	if len(r.Responses) == 0 {
		return errors.New("ocsp: response without single responses")
	}
	if r.Extensions, err = readExtensions(&seq, 1); err != nil {
		return err
	}
	if !seq.Empty() {
		return errors.New("ocsp: trailing data in ResponseData")
	}
	return nil
}

func parseSingleResponse(in *cryptobyte.String) (*SingleResponse, error) {
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, errors.New("ocsp: malformed SingleResponse")
	}
	id, err := parseCertID(&seq)
	if err != nil {
		return nil, err
	}
	sr := &SingleResponse{CertID: id, RevocationReason: -1}
	var status cryptobyte.String
	var tag cbasn1.Tag
	if !seq.ReadAnyASN1(&status, &tag) {
		return nil, errors.New("ocsp: malformed certStatus")
	}
	switch tag {
	case cbasn1.Tag(0).ContextSpecific():
		sr.Status = Good
		if !status.Empty() {
			return nil, errors.New("ocsp: malformed certStatus good")
		}
	case cbasn1.Tag(2).ContextSpecific():
		sr.Status = Unknown
		if !status.Empty() {
			return nil, errors.New("ocsp: malformed certStatus unknown")
		}
	case cbasn1.Tag(1).Constructed().ContextSpecific():
		sr.Status = Revoked
		if sr.RevokedAt, err = readGeneralizedTime(&status); err != nil {
			return nil, fmt.Errorf("ocsp: revocationTime: %w", err)
		}
		if status.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific()) {
			var reason cryptobyte.String
			var v int
			if !status.ReadASN1(&reason, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
				!reason.ReadASN1Enum(&v) || !reason.Empty() || v < 0 || v > 10 {
				return nil, errors.New("ocsp: malformed revocationReason")
			}
			sr.RevocationReason = v
		}
		if !status.Empty() {
			return nil, errors.New("ocsp: malformed RevokedInfo")
		}
	default:
		return nil, errors.New("ocsp: malformed certStatus")
	}
	if sr.ThisUpdate, err = readGeneralizedTime(&seq); err != nil {
		return nil, fmt.Errorf("ocsp: thisUpdate: %w", err)
	}
	if seq.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific()) {
		var next cryptobyte.String
		if !seq.ReadASN1(&next, cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("ocsp: malformed nextUpdate")
		}
		if sr.NextUpdate, err = readGeneralizedTime(&next); err != nil || !next.Empty() {
			return nil, errors.New("ocsp: malformed nextUpdate")
		}
	}
	if sr.Extensions, err = readExtensions(&seq, 1); err != nil {
		return nil, err
	}
	if !seq.Empty() {
		return nil, errors.New("ocsp: trailing data in SingleResponse")
	}
	for _, e := range sr.Extensions {
		if e.Id.Equal(OIDCertHash) {
			if sr.CertHash, err = parseCertHash(e.Value); err != nil {
				return nil, err
			}
		}
	}
	return sr, nil
}

// parseCertHash parses CertHash ::= SEQUENCE { hashAlgorithm
// AlgorithmIdentifier, certificateHash OCTET STRING }.
func parseCertHash(der []byte) (*CertHash, error) {
	in := cryptobyte.String(der)
	var seq, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	ch := new(CertHash)
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() ||
		!seq.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return nil, errors.New("ocsp: malformed certHash")
	}
	var null cryptobyte.String
	if alg.PeekASN1Tag(cbasn1.NULL) && (!alg.ReadASN1(&null, cbasn1.NULL) || !null.Empty()) || !alg.Empty() {
		return nil, errors.New("ocsp: malformed certHash algorithm")
	}
	if !seq.ReadASN1Bytes(&ch.Hash, cbasn1.OCTET_STRING) || !seq.Empty() {
		return nil, errors.New("ocsp: malformed certHash")
	}
	ch.HashAlgorithm = hashForOID(oid)
	if ch.HashAlgorithm == 0 {
		return nil, fmt.Errorf("ocsp: unsupported certHash algorithm %v", oid)
	}
	return ch, nil
}

// readExtensions reads an optional [tag] EXPLICIT Extensions field.
func readExtensions(s *cryptobyte.String, tag uint8) ([]pkix.Extension, error) {
	var outer cryptobyte.String
	var present bool
	if !s.ReadOptionalASN1(&outer, &present, cbasn1.Tag(tag).Constructed().ContextSpecific()) {
		return nil, errors.New("ocsp: malformed extensions")
	}
	if !present {
		return nil, nil
	}
	var list cryptobyte.String
	if !outer.ReadASN1(&list, cbasn1.SEQUENCE) || !outer.Empty() {
		return nil, errors.New("ocsp: malformed extensions")
	}
	var exts []pkix.Extension
	for !list.Empty() {
		var e cryptobyte.String
		var ext pkix.Extension
		if !list.ReadASN1(&e, cbasn1.SEQUENCE) || !e.ReadASN1ObjectIdentifier(&ext.Id) ||
			!e.ReadOptionalASN1Boolean(&ext.Critical, cbasn1.BOOLEAN, false) ||
			!e.ReadASN1Bytes(&ext.Value, cbasn1.OCTET_STRING) || !e.Empty() {
			return nil, errors.New("ocsp: malformed extension")
		}
		for _, prev := range exts {
			if prev.Id.Equal(ext.Id) {
				return nil, fmt.Errorf("ocsp: duplicate extension %v", ext.Id)
			}
		}
		exts = append(exts, ext)
	}
	return exts, nil
}

// readGeneralizedTime reads a GeneralizedTime in the form of RFC 5280,
// Section 4.1.2.5.2, and also accepts fractional seconds (DER, X.690
// Section 11.7), which some OCSP responders write.
func readGeneralizedTime(s *cryptobyte.String) (time.Time, error) {
	var b cryptobyte.String
	if !s.ReadASN1(&b, cbasn1.GeneralizedTime) {
		return time.Time{}, errors.New("malformed GeneralizedTime")
	}
	str := string(b)
	if len(str) < 15 || str[len(str)-1] != 'Z' {
		return time.Time{}, errors.New("malformed GeneralizedTime")
	}
	body := str[:len(str)-1]
	if len(body) > 14 {
		frac := body[14:]
		if len(frac) < 2 || frac[0] != '.' || frac[len(frac)-1] == '0' {
			return time.Time{}, errors.New("malformed GeneralizedTime")
		}
		for _, c := range frac[1:] {
			if c < '0' || c > '9' {
				return time.Time{}, errors.New("malformed GeneralizedTime")
			}
		}
	}
	for _, c := range body[:14] {
		if c < '0' || c > '9' {
			return time.Time{}, errors.New("malformed GeneralizedTime")
		}
	}
	t, err := time.Parse("20060102150405.999999999", body)
	if err != nil {
		return time.Time{}, errors.New("malformed GeneralizedTime")
	}
	return t.UTC(), nil
}

// signatureAlgorithm maps a DER AlgorithmIdentifier to an
// x509.SignatureAlgorithm. SHA-1 algorithms are mapped so that
// x509util.CheckSignature rejects them as insecure.
func signatureAlgorithm(der []byte) x509.SignatureAlgorithm {
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&oid) {
		return x509.UnknownSignatureAlgorithm
	}
	nullOrEmpty := seq.Empty() || bytes.Equal(seq, []byte{5, 0})
	switch {
	case oid.Equal(oidECDSAWithSHA256) && seq.Empty():
		return x509.ECDSAWithSHA256
	case oid.Equal(oidECDSAWithSHA384) && seq.Empty():
		return x509.ECDSAWithSHA384
	case oid.Equal(oidECDSAWithSHA512) && seq.Empty():
		return x509.ECDSAWithSHA512
	case oid.Equal(oidECDSAWithSHA1):
		return x509.ECDSAWithSHA1
	case oid.Equal(oidSHA256WithRSA) && nullOrEmpty:
		return x509.SHA256WithRSA
	case oid.Equal(oidSHA384WithRSA) && nullOrEmpty:
		return x509.SHA384WithRSA
	case oid.Equal(oidSHA512WithRSA) && nullOrEmpty:
		return x509.SHA512WithRSA
	case oid.Equal(oidSHA1WithRSA):
		return x509.SHA1WithRSA
	case oid.Equal(oidRSAPSS):
		return pssAlgorithm(seq)
	}
	return x509.UnknownSignatureAlgorithm
}

// pssAlgorithm maps RSASSA-PSS-params (RFC 4055) with SHA-256, -384 or
// -512, MGF1 with the same hash and a salt as long as the hash (the forms
// crypto/x509 verifies) to an x509.SignatureAlgorithm.
func pssAlgorithm(params cryptobyte.String) x509.SignatureAlgorithm {
	var seq, hashAlg, mgf, mgfAlg, mgfHash cryptobyte.String
	var hashOID, mgfOID, mgfHashOID asn1.ObjectIdentifier
	var salt int64
	if !params.ReadASN1(&seq, cbasn1.SEQUENCE) || !params.Empty() ||
		!seq.ReadASN1(&hashAlg, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!hashAlg.ReadASN1(&hashAlg, cbasn1.SEQUENCE) || !hashAlg.ReadASN1ObjectIdentifier(&hashOID) ||
		!seq.ReadASN1(&mgf, cbasn1.Tag(1).Constructed().ContextSpecific()) ||
		!mgf.ReadASN1(&mgfAlg, cbasn1.SEQUENCE) || !mgfAlg.ReadASN1ObjectIdentifier(&mgfOID) ||
		!mgfAlg.ReadASN1(&mgfHash, cbasn1.SEQUENCE) || !mgfHash.ReadASN1ObjectIdentifier(&mgfHashOID) ||
		!seq.ReadOptionalASN1Integer(&salt, cbasn1.Tag(2).Constructed().ContextSpecific(), int64(20)) {
		return x509.UnknownSignatureAlgorithm
	}
	h := hashForOID(hashOID)
	if !mgfOID.Equal(oidMGF1) || !mgfHashOID.Equal(hashOID) || h == 0 || h == crypto.SHA1 || salt != int64(h.Size()) {
		return x509.UnknownSignatureAlgorithm
	}
	switch h {
	case crypto.SHA256:
		return x509.SHA256WithRSAPSS
	case crypto.SHA384:
		return x509.SHA384WithRSAPSS
	}
	return x509.SHA512WithRSAPSS
}

// CheckSignatureFrom checks that r is signed by signer's key, which may be
// a Brainpool key. It checks nothing else about signer.
func (r *Response) CheckSignatureFrom(signer *x509.Certificate) error {
	if r.Status != Successful {
		return fmt.Errorf("ocsp: response status %v has no signature", r.Status)
	}
	if r.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return fmt.Errorf("ocsp: unsupported signature algorithm: %w", x509.ErrUnsupportedAlgorithm)
	}
	pub, err := x509util.PublicKey(signer)
	if err != nil {
		return err
	}
	return x509util.CheckSignature(r.SignatureAlgorithm, r.TBSResponseData, r.Signature, pub)
}

// Nonce returns the value of the nonce extension of r, or nil.
func (r *Response) Nonce() []byte {
	for _, e := range r.Extensions {
		if e.Id.Equal(OIDNonce) {
			return e.Value
		}
	}
	return nil
}
