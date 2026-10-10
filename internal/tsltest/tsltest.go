// Package tsltest builds TSLs of the TI's form for tests: test services,
// the XML, and a signature as the TSL service makes it.
package tsltest

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/internal/testpki"
	"github.com/DominicBreuker/ivory/internal/xmldsig"
)

// A Service describes a TSPService of a test TSL. Zero Status means
// inaccord, zero Start means testpki.Start.
type Service struct {
	Type, Status  string
	Start         time.Time
	Certs         []*x509.Certificate
	SupplyPoints  []string
	ExtensionOIDs []string
	Name          string
}

func (s Service) xml() string {
	var b strings.Builder
	name := s.Name
	if name == "" {
		name = "service"
	}
	if s.Status == "" {
		s.Status = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord"
	}
	if s.Start.IsZero() {
		s.Start = testpki.Start
	}
	fmt.Fprintf(&b, "<TSPService><ServiceInformation><ServiceTypeIdentifier>%s</ServiceTypeIdentifier>"+
		`<ServiceName><Name xml:lang="DE">%s</Name></ServiceName><ServiceDigitalIdentity>`, s.Type, name)
	for _, c := range s.Certs {
		fmt.Fprintf(&b, "<DigitalId><X509Certificate>%s</X509Certificate></DigitalId>", base64.StdEncoding.EncodeToString(c.Raw))
	}
	fmt.Fprintf(&b, "</ServiceDigitalIdentity><ServiceStatus>%s</ServiceStatus><StatusStartingTime>%s</StatusStartingTime>",
		s.Status, s.Start.UTC().Format(time.RFC3339))
	if len(s.SupplyPoints) > 0 {
		b.WriteString("<ServiceSupplyPoints>")
		for _, p := range s.SupplyPoints {
			fmt.Fprintf(&b, "<ServiceSupplyPoint>%s</ServiceSupplyPoint>", p)
		}
		b.WriteString("</ServiceSupplyPoints>")
	}
	if len(s.ExtensionOIDs) > 0 {
		b.WriteString("<ServiceInformationExtensions>")
		for _, o := range s.ExtensionOIDs {
			fmt.Fprintf(&b, `<Extension Critical="false"><ns:ExtensionOID xmlns:ns="http://uri.etsi.org/02231/v2#">%s</ns:ExtensionOID>`+
				`<ns:ExtensionValue xmlns:ns="http://uri.etsi.org/02231/v2#">x</ns:ExtensionValue></Extension>`, o)
		}
		b.WriteString("</ServiceInformationExtensions>")
	}
	b.WriteString("</ServiceInformation></TSPService>")
	return b.String()
}

// XML returns the XML of a TSL with sequence number seq, NextUpdate next,
// the download points primary and backup, and the given services, without
// a signature. It is issued an hour before next minus 30 days.
func XML(seq int, next time.Time, primary, backup string, services ...Service) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
		`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="ID%d" TSLTag="http://uri.etsi.org/02231/TSLTag">`+
		`<SchemeInformation><TSLVersionIdentifier>3</TSLVersionIdentifier><TSLSequenceNumber>%d</TSLSequenceNumber>`+
		`<TSLType>http://uri.etsi.org/TrstSvc/TSLtype/generic</TSLType>`+
		`<SchemeOperatorName><Name xml:lang="DE">ivory test</Name></SchemeOperatorName>`+
		`<SchemeOperatorAddress><PostalAddresses><PostalAddress xml:lang="DE"><StreetAddress>Street 1</StreetAddress>`+
		`<Locality>Berlin</Locality><CountryName>DE</CountryName></PostalAddress></PostalAddresses>`+
		`<ElectronicAddress><URI>mailto:test@example.com</URI></ElectronicAddress></SchemeOperatorAddress>`+
		`<SchemeName><Name xml:lang="DE">ivory test scheme</Name></SchemeName>`+
		`<SchemeInformationURI><URI xml:lang="DE">http://example.com</URI></SchemeInformationURI>`+
		`<StatusDeterminationApproach>http://uri.etsi.org/TrstSvc/TSLType/StatusDetn/passive</StatusDeterminationApproach>`+
		`<HistoricalInformationPeriod>0</HistoricalInformationPeriod>`+
		`<PointersToOtherTSL><OtherTSLPointer><TSLLocation>%s</TSLLocation>`+
		`<AdditionalInformation><TextualInformation xml:lang="DE">1.2.276.0.76.4.120</TextualInformation></AdditionalInformation></OtherTSLPointer>`+
		`<OtherTSLPointer><TSLLocation>%s</TSLLocation>`+
		`<AdditionalInformation><TextualInformation xml:lang="DE">1.2.276.0.76.4.121</TextualInformation></AdditionalInformation></OtherTSLPointer></PointersToOtherTSL>`+
		`<ListIssueDateTime>%s</ListIssueDateTime><NextUpdate><dateTime>%s</dateTime></NextUpdate></SchemeInformation>`,
		seq, seq, primary, backup, next.Add(-30*24*time.Hour-time.Hour).UTC().Format(time.RFC3339), next.UTC().Format(time.RFC3339))
	if len(services) > 0 {
		b.WriteString(`<TrustServiceProviderList><TrustServiceProvider><TSPInformation><TSPName><Name xml:lang="DE">ivory TSP</Name></TSPName>` +
			`<TSPAddress><PostalAddresses><PostalAddress xml:lang="DE"><StreetAddress>Street 1</StreetAddress><Locality>Berlin</Locality>` +
			`<CountryName>DE</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI>mailto:tsp@example.com</URI></ElectronicAddress></TSPAddress>` +
			`<TSPInformationURI><URI xml:lang="DE">http://tsp.example</URI></TSPInformationURI></TSPInformation><TSPServices>`)
		for _, s := range services {
			b.WriteString(s.xml())
		}
		b.WriteString(`</TSPServices></TrustServiceProvider></TrustServiceProviderList>`)
	}
	b.WriteString("</TrustServiceStatusList>")
	return b.String()
}

// Sign adds an enveloped signature to the unsigned TSL xml, made with key,
// the key of signer, the way the TSL service signs.
func Sign(t testing.TB, unsigned string, signer *x509.Certificate, key crypto.Signer) []byte {
	t.Helper()
	data, err := xmldsig.SignEnveloped([]byte(unsigned), signer, key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
