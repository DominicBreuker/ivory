//go:build ivory

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// oidAdmission is the admission extension of Common PKI (id-isismtt-at-
// admission), which carries the roles of TI certificates.
var oidAdmission = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3}

// A CertInfo describes a certificate the way TI products look at it.
type CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	Serial       string    `json:"serial"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Key          string    `json:"key"`
	SignatureAlg string    `json:"signature_algorithm"`
	IsCA         bool      `json:"ca,omitempty"`
	KeyUsage     []string  `json:"key_usage,omitempty"`
	ExtKeyUsage  []string  `json:"extended_key_usage,omitempty"`
	// Policies are the certificate policies; TI certificate types are
	// named (C.HCI.AUT, C.FD.TLS-S, ...).
	Policies []NamedOID `json:"policies,omitempty"`
	// Types are the TI certificate types among the policies.
	Types      []string   `json:"ti_types,omitempty"`
	Admission  *Admission `json:"admission,omitempty"`
	DNSNames   []string   `json:"dns_names,omitempty"`
	IPs        []string   `json:"ip_addresses,omitempty"`
	Emails     []string   `json:"emails,omitempty"`
	OCSP       []string   `json:"ocsp_servers,omitempty"`
	CRL        []string   `json:"crl_distribution_points,omitempty"`
	SubjectKey string     `json:"subject_key_id,omitempty"`
	AuthKey    string     `json:"authority_key_id,omitempty"`
	SHA256     string     `json:"sha256"`
	// Error is set when the certificate doesn't parse.
	Error string `json:"error,omitempty"`
}

// A NamedOID is an OID with its name from gemSpec_OID, if known.
type NamedOID struct {
	OID  string `json:"oid"`
	Name string `json:"name,omitempty"`
}

func (n NamedOID) String() string {
	if n.Name == "" {
		return n.OID
	}
	return n.Name + " (" + n.OID + ")"
}

func nameOID(oid string) NamedOID {
	n := NamedOID{OID: oid}
	if v, ok := tiOIDs[oid]; ok {
		n.Name = v[0]
		if v[1] != "" {
			n.Name = v[1] + " = " + v[0]
		}
	}
	return n
}

// An Admission is the content of the admission extension: the roles of
// the certificate holder (gemSpec_PKI; Common PKI part 4).
type Admission struct {
	Professions []Profession `json:"professions"`
}

// A Profession is one ProfessionInfo of the admission extension.
type Profession struct {
	Items              []string   `json:"items,omitempty"`
	OIDs               []NamedOID `json:"oids,omitempty"`
	RegistrationNumber string     `json:"registration_number,omitempty"`
}

// describeDER parses a DER certificate and describes it.
func describeDER(der []byte) CertInfo {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		sum := sha256.Sum256(der)
		return CertInfo{Error: err.Error(), SHA256: hex.EncodeToString(sum[:])}
	}
	return describe(c)
}

func describe(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.Raw)
	info := CertInfo{
		Subject:      c.Subject.String(),
		Issuer:       c.Issuer.String(),
		Serial:       hex.EncodeToString(c.SerialNumber.Bytes()),
		NotBefore:    c.NotBefore.UTC(),
		NotAfter:     c.NotAfter.UTC(),
		Key:          keyDescription(c),
		SignatureAlg: c.SignatureAlgorithm.String(),
		IsCA:         c.BasicConstraintsValid && c.IsCA,
		DNSNames:     c.DNSNames,
		Emails:       c.EmailAddresses,
		OCSP:         c.OCSPServer,
		CRL:          c.CRLDistributionPoints,
		SHA256:       hex.EncodeToString(sum[:]),
	}
	for _, ip := range c.IPAddresses {
		info.IPs = append(info.IPs, ip.String())
	}
	if len(c.SubjectKeyId) > 0 {
		info.SubjectKey = hex.EncodeToString(c.SubjectKeyId)
	}
	if len(c.AuthorityKeyId) > 0 {
		info.AuthKey = hex.EncodeToString(c.AuthorityKeyId)
	}
	for bit := x509.KeyUsage(1); bit != 0 && bit <= c.KeyUsage; bit <<= 1 {
		if c.KeyUsage&bit != 0 {
			info.KeyUsage = append(info.KeyUsage, bit.String())
		}
	}
	for _, u := range c.ExtKeyUsage {
		info.ExtKeyUsage = append(info.ExtKeyUsage, extKeyUsageName(u))
	}
	for _, u := range c.UnknownExtKeyUsage {
		info.ExtKeyUsage = append(info.ExtKeyUsage, u.String())
	}
	for _, p := range c.Policies {
		n := nameOID(p.String())
		info.Policies = append(info.Policies, n)
		if v, ok := tiOIDs[p.String()]; ok && strings.HasPrefix(v[1], "C.") {
			info.Types = append(info.Types, v[1])
		}
	}
	for _, e := range c.Extensions {
		if e.Id.Equal(oidAdmission) {
			a, err := parseAdmission(e.Value)
			if err != nil {
				info.Admission = &Admission{Professions: []Profession{{Items: []string{"(malformed: " + err.Error() + ")"}}}}
			} else {
				info.Admission = a
			}
		}
	}
	return info
}

func keyDescription(c *x509.Certificate) string {
	pub, err := x509util.PublicKey(c)
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	switch k := pub.(type) {
	case *brainpool.PublicKey:
		return "ECDSA " + k.Curve().String()
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", pub)
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:             "any",
	x509.ExtKeyUsageServerAuth:      "serverAuth",
	x509.ExtKeyUsageClientAuth:      "clientAuth",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
}

func extKeyUsageName(u x509.ExtKeyUsage) string {
	if n, ok := extKeyUsageNames[u]; ok {
		return n
	}
	return fmt.Sprintf("extKeyUsage(%d)", u)
}

// parseAdmission parses the admission extension:
//
//	AdmissionSyntax ::= SEQUENCE {
//	  admissionAuthority GeneralName OPTIONAL,
//	  contentsOfAdmissions SEQUENCE OF Admissions }
//	Admissions ::= SEQUENCE {
//	  admissionAuthority [0] EXPLICIT GeneralName OPTIONAL,
//	  namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL,
//	  professionInfos SEQUENCE OF ProfessionInfo }
//	ProfessionInfo ::= SEQUENCE {
//	  namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
//	  professionItems SEQUENCE OF DirectoryString,
//	  professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
//	  registrationNumber PrintableString OPTIONAL,
//	  addProfessionInfo OCTET STRING OPTIONAL }
func parseAdmission(der []byte) (*Admission, error) {
	errBad := fmt.Errorf("bad admission extension")
	in := cryptobyte.String(der)
	var syntax, contents cryptobyte.String
	if !in.ReadASN1(&syntax, cbasn1.SEQUENCE) {
		return nil, errBad
	}
	// admissionAuthority is a GeneralName, a CHOICE of context-specific
	// tags: skip it if present.
	if !syntax.PeekASN1Tag(cbasn1.SEQUENCE) {
		var skip cryptobyte.String
		var tag cbasn1.Tag
		if !syntax.ReadAnyASN1Element(&skip, &tag) {
			return nil, errBad
		}
	}
	if !syntax.ReadASN1(&contents, cbasn1.SEQUENCE) {
		return nil, errBad
	}
	a := &Admission{}
	for !contents.Empty() {
		var adm, infos cryptobyte.String
		if !contents.ReadASN1(&adm, cbasn1.SEQUENCE) ||
			!adm.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) ||
			!adm.SkipOptionalASN1(cbasn1.Tag(1).Constructed().ContextSpecific()) ||
			!adm.ReadASN1(&infos, cbasn1.SEQUENCE) {
			return nil, errBad
		}
		for !infos.Empty() {
			var info, items cryptobyte.String
			if !infos.ReadASN1(&info, cbasn1.SEQUENCE) ||
				!info.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) ||
				!info.ReadASN1(&items, cbasn1.SEQUENCE) {
				return nil, errBad
			}
			var p Profession
			for !items.Empty() {
				var item cryptobyte.String
				var tag cbasn1.Tag
				if !items.ReadAnyASN1(&item, &tag) {
					return nil, errBad
				}
				p.Items = append(p.Items, directoryString(item, tag))
			}
			if info.PeekASN1Tag(cbasn1.SEQUENCE) {
				var oids cryptobyte.String
				if !info.ReadASN1(&oids, cbasn1.SEQUENCE) {
					return nil, errBad
				}
				for !oids.Empty() {
					var oid asn1.ObjectIdentifier
					if !oids.ReadASN1ObjectIdentifier(&oid) {
						return nil, errBad
					}
					p.OIDs = append(p.OIDs, nameOID(oid.String()))
				}
			}
			if info.PeekASN1Tag(cbasn1.PrintableString) {
				var reg cryptobyte.String
				if !info.ReadASN1(&reg, cbasn1.PrintableString) {
					return nil, errBad
				}
				p.RegistrationNumber = string(reg)
			}
			a.Professions = append(a.Professions, p)
		}
	}
	return a, nil
}

// directoryString decodes a DirectoryString: UTF8String, PrintableString
// and the other single-byte types as they are, BMPString as UTF-16.
func directoryString(b []byte, tag cbasn1.Tag) string {
	if tag == cbasn1.Tag(30) { // BMPString
		var r []rune
		for i := 0; i+1 < len(b); i += 2 {
			r = append(r, rune(b[i])<<8|rune(b[i+1]))
		}
		return string(r)
	}
	return string(b)
}
