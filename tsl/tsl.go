package tsl

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/DominicBreuker/ivory/internal/xmldsig"
	"strconv"
	"strings"
	"time"

	"github.com/DominicBreuker/ivory/x509util"
)

// Service type identifiers used in the TI's TSL (gemSpec_PKI V2.28.0,
// Section 8.1; ETSI TS 102 231).
const (
	TypeCA                = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"
	TypeOCSP              = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP"
	TypeCRL               = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL"
	TypeTSLServiceCertChg = "http://uri.etsi.org/TrstSvc/Svctype/TSLServiceCertChange"
	TypeUnspecified       = "http://uri.etsi.org/TrstSvc/Svctype/unspecified"
)

// Service statuses allowed in the TI's TSL (gemSpec_PKI V2.28.0,
// Tab_PKI_271).
const (
	StatusInAccord = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord"
	StatusRevoked  = "http://uri.etsi.org/TrstSvc/Svcstatus/revoked"
)

// OIDs of the TSL download points in PointersToOtherTSL (gemSpec_OID
// V3.26.0: oid_tsl_p_loc, oid_tsl_b_loc). The TSL tags each TSLLocation
// with one of them as TextualInformation.
const (
	OIDPrimaryLocation = "1.2.276.0.76.4.120"
	OIDBackupLocation  = "1.2.276.0.76.4.121"
)

// A TSL is a parsed trust-service status list of the TI.
type TSL struct {
	// Raw is the document as parsed.
	Raw []byte

	// ID is the Id attribute of the root element.
	ID             string
	SequenceNumber int64
	IssueDate      time.Time
	// NextUpdate is the zero time if the TSL has none ("closed" TSL).
	NextUpdate time.Time

	// PrimaryLocations and BackupLocations are the download URLs of
	// PointersToOtherTSL marked with OIDPrimaryLocation and
	// OIDBackupLocation.
	PrimaryLocations, BackupLocations []string

	Services []*Service

	doc *xmldsig.Document
}

// A Service is one TSPService entry.
type Service struct {
	// Provider is the first TSPName of the trust service provider.
	Provider string
	Type     string
	Name     string
	// Certificates are the DER X509Certificate digital identities.
	Certificates [][]byte
	Status       string
	StatusStart  time.Time
	SupplyPoints []string
	// ExtensionOIDs are the values of the ExtensionOID elements of the
	// ServiceInformationExtensions: in the TI, the certificate types the
	// CA may issue (oid_hba_aut, oid_smc_b_osig, ...) and markers such as
	// oid_tsl_cca_cert.
	ExtensionOIDs []string
	// History are the ServiceHistoryInstance entries, newest first as in
	// the TSL.
	History []HistoryEntry

	certs []*x509.Certificate
}

// A HistoryEntry is an earlier status of a service.
type HistoryEntry struct {
	Type        string
	Status      string
	StatusStart time.Time
}

// Parse parses a TSL and checks it against the XML schema of ETSI TS 102
// 231 (TUC_PKI_020). It doesn't check the signature; see Verify.
//
// The XML must be UTF-8 without a DTD, and attribute values must not
// contain tabs or line breaks.
func Parse(data []byte) (*TSL, error) {
	doc, err := xmldsig.Parse(data)
	if err != nil {
		return nil, err
	}
	if err := checkSchema(doc); err != nil {
		return nil, err
	}
	t := &TSL{Raw: data, doc: doc}
	t.ID, _ = doc.Root.Attr("Id")
	si := doc.Root.Child(nsTSL, "SchemeInformation")
	if t.SequenceNumber, err = strconv.ParseInt(collapse(si.Child(nsTSL, "TSLSequenceNumber").Text()), 10, 64); err != nil {
		return nil, fmt.Errorf("tsl: TSLSequenceNumber: %w", err)
	}
	t.IssueDate, _ = parseDateTime(si.Child(nsTSL, "ListIssueDateTime").Text())
	if dt := si.Child(nsTSL, "NextUpdate").Child(nsTSL, "dateTime"); dt != nil {
		t.NextUpdate, _ = parseDateTime(dt.Text())
	}
	if p := si.Child(nsTSL, "PointersToOtherTSL"); p != nil {
		for _, o := range p.Children() {
			loc := collapse(o.Child(nsTSL, "TSLLocation").Text())
			if ai := o.Child(nsTSL, "AdditionalInformation"); ai != nil {
				for _, ti := range ai.Children() {
					switch collapse(ti.Text()) {
					case OIDPrimaryLocation:
						t.PrimaryLocations = append(t.PrimaryLocations, loc)
					case OIDBackupLocation:
						t.BackupLocations = append(t.BackupLocations, loc)
					}
				}
			}
		}
	}
	if list := doc.Root.Child(nsTSL, "TrustServiceProviderList"); list != nil {
		for _, tsp := range list.Children() {
			provider := tsp.Child(nsTSL, "TSPInformation").Child(nsTSL, "TSPName").Children()[0].Text()
			for _, svc := range tsp.Child(nsTSL, "TSPServices").Children() {
				t.Services = append(t.Services, parseService(provider, svc))
			}
		}
	}
	return t, nil
}

func parseService(provider string, svc *xmldsig.Element) *Service {
	info := svc.Child(nsTSL, "ServiceInformation")
	s := &Service{
		Provider: provider,
		Type:     collapse(info.Child(nsTSL, "ServiceTypeIdentifier").Text()),
		Name:     info.Child(nsTSL, "ServiceName").Children()[0].Text(),
		Status:   collapse(info.Child(nsTSL, "ServiceStatus").Text()),
	}
	s.StatusStart, _ = parseDateTime(info.Child(nsTSL, "StatusStartingTime").Text())
	for _, id := range info.Child(nsTSL, "ServiceDigitalIdentity").Children() {
		if c := id.Child(nsTSL, "X509Certificate"); c != nil {
			der, _ := xmldsig.DecodeBase64(c.Text())
			s.Certificates = append(s.Certificates, der)
		}
	}
	if ssp := info.Child(nsTSL, "ServiceSupplyPoints"); ssp != nil {
		for _, p := range ssp.Children() {
			s.SupplyPoints = append(s.SupplyPoints, collapse(p.Text()))
		}
	}
	s.ExtensionOIDs = extensionOIDs(info.Child(nsTSL, "ServiceInformationExtensions"))
	if h := svc.Child(nsTSL, "ServiceHistory"); h != nil {
		for _, inst := range h.Children() {
			e := HistoryEntry{
				Type:   collapse(inst.Child(nsTSL, "ServiceTypeIdentifier").Text()),
				Status: collapse(inst.Child(nsTSL, "ServiceStatus").Text()),
			}
			e.StatusStart, _ = parseDateTime(inst.Child(nsTSL, "StatusStartingTime").Text())
			s.History = append(s.History, e)
		}
	}
	for _, der := range s.Certificates {
		// Certificates that don't parse are skipped: "Nach erfolgreichen
		// Schema- und Signatur-Prüfungen darf es bei der Verarbeitung der
		// TSL-Elemente nicht mehr zum Abbruch des TUC kommen" (TUC_PKI_001).
		if c, err := x509.ParseCertificate(der); err == nil {
			s.certs = append(s.certs, c)
		}
	}
	return s
}

// extensionOIDs returns the text of the ExtensionOID elements (in the TSL
// namespace) of the extensions in list.
func extensionOIDs(list *xmldsig.Element) []string {
	if list == nil {
		return nil
	}
	var oids []string
	for _, ext := range list.Children() {
		for _, c := range ext.Children() {
			if c.Is(nsTSL, "ExtensionOID") {
				oids = append(oids, collapse(c.Text()))
			}
		}
	}
	return oids
}

// ParsedCertificates returns the certificates of s that crypto/x509
// parses. With the ivory overlay, that includes Brainpool certificates.
func (s *Service) ParsedCertificates() []*x509.Certificate { return s.certs }

// HasExtensionOID reports whether oid is one of s's ExtensionOIDs.
func (s *Service) HasExtensionOID(oid string) bool {
	for _, o := range s.ExtensionOIDs {
		if o == oid {
			return true
		}
	}
	return false
}

// Hash returns the SHA-256 hash of the TSL as downloaded, the value of the
// TSL service's hash file (gemSpec_PKI TUC_PKI_019).
func (t *TSL) Hash() [32]byte { return sha256.Sum256(t.Raw) }

// ServicesOfType returns the services with the given type identifier.
func (t *TSL) ServicesOfType(typ string) []*Service {
	var out []*Service
	for _, s := range t.Services {
		if s.Type == typ {
			out = append(out, s)
		}
	}
	return out
}

// CAs returns the CA certificates of the TI trust space: the parsable
// certificates of the CA/PKC services with status inaccord or revoked
// (gemSpec_PKI V2.28.0, TUC_PKI_001 step 6 and Tab_PKI_271). A revoked
// CA's certificates stay, because the certificates it issued before its
// StatusStartingTime remain valid; StatusCheck handles that.
func (t *TSL) CAs() []*x509.Certificate {
	var out []*x509.Certificate
	for _, s := range t.ServicesOfType(TypeCA) {
		if s.Status == StatusInAccord || s.Status == StatusRevoked {
			out = append(out, s.certs...)
		}
	}
	return out
}

// OCSPResponders returns the certificates of the OCSP services with status
// inaccord, the only certificates that may sign OCSP responses
// (TUC_PKI_006 step 5).
func (t *TSL) OCSPResponders() []*x509.Certificate {
	var out []*x509.Certificate
	for _, s := range t.ServicesOfType(TypeOCSP) {
		if s.Status == StatusInAccord {
			out = append(out, s.certs...)
		}
	}
	return out
}

// ErrCAMissing is wrapped by the errors of IssuerService when no CA
// service has the issuer (CA_CERT_MISSING, TUC_PKI_003).
var ErrCAMissing = errors.New("CA_CERT_MISSING")

// IssuerService returns the CA/PKC service whose certificate issued cert:
// its subject is cert's issuer and, if both have key identifiers, its
// subject key identifier is cert's authority key identifier (TUC_PKI_003),
// and its key verifies cert's signature. It also returns that CA
// certificate.
func (t *TSL) IssuerService(cert *x509.Certificate) (*Service, *x509.Certificate, error) {
	var sigErr error
	for _, s := range t.ServicesOfType(TypeCA) {
		for _, ca := range s.certs {
			if !bytes.Equal(cert.RawIssuer, ca.RawSubject) {
				continue
			}
			if len(cert.AuthorityKeyId) > 0 && len(ca.SubjectKeyId) > 0 && !bytes.Equal(cert.AuthorityKeyId, ca.SubjectKeyId) {
				continue
			}
			if err := x509util.CheckCertificateSignatureFrom(cert, ca); err != nil {
				sigErr = err
				continue
			}
			return s, ca, nil
		}
	}
	if sigErr != nil {
		return nil, nil, fmt.Errorf("tsl: certificate %q: bad signature by its CA: %w", cert.Subject, sigErr)
	}
	return nil, nil, fmt.Errorf("tsl: no CA for %q in the TSL: %w", cert.Issuer, ErrCAMissing)
}

// ServiceOf returns the service of the given type that lists cert, or nil.
func (t *TSL) ServiceOf(typ string, cert *x509.Certificate) *Service {
	for _, s := range t.ServicesOfType(typ) {
		for _, der := range s.Certificates {
			if bytes.Equal(der, cert.Raw) {
				return s
			}
		}
	}
	return nil
}

// OCSPLocation returns the first ServiceSupplyPoint of s that is an HTTP
// URL (TUC_PKI_005), or "".
func (s *Service) OCSPLocation() string {
	for _, p := range s.SupplyPoints {
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			return p
		}
	}
	return ""
}
