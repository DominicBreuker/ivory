package tsl

import (
	"encoding/base64"
	"fmt"
	"github.com/DominicBreuker/ivory/internal/xmldsig"
	"math/big"
	"strings"
	"time"
)

// A structural check of the TSL against the XML schema of ETSI TS 102 231
// V3.1.2 (Annex C, ts_102231v030102_xsd.xsd), which gemSpec_PKI
// TUC_PKI_020 (GS-A_4649) requires: element names, order and number,
// required and unknown attributes, and the simple types of the text
// content. Content of type AnyType (extensions, OtherInformation, Other)
// is processed laxly, as the schema says; the ds:Signature element is
// checked by the signature verification.

const nsTSL = "http://uri.etsi.org/02231/v2#"

type simpleKind int

const (
	sNone        simpleKind = iota // element-only content
	sString                        // xsd:string
	sNonEmpty                      // NonEmptyString, NonEmptyNormalizedString
	sURI                           // NonEmptyURIType
	sInteger                       // xsd:integer
	sPositive                      // xsd:positiveInteger
	sNonNegative                   // xsd:nonNegativeInteger
	sDateTime                      // xsd:dateTime
	sBase64                        // xsd:base64Binary
	sTerritory                     // two characters
)

type particle struct {
	Space, Local string
	min, max     int // max < 0: unbounded
	typ          *ctype
}

type ctype struct {
	simple simpleKind
	// lang says the xml:lang attribute is required.
	lang bool
	// Attrs are further allowed attributes and whether they are required.
	Attrs map[string]bool
	// any: mixed content, any child elements (lax).
	any bool
	// seq is the sequence of child particles; if choice is set, each
	// child must match one of them, between choiceMin and choiceMax
	// children in total, and uniform requires all children to have the
	// same name.
	seq                  []particle
	choice, uniform      bool
	choiceMin, choiceMax int
}

func el(local string, min, max int, t *ctype) particle {
	return particle{nsTSL, local, min, max, t}
}

var (
	tString     = &ctype{simple: sString}
	tNonEmpty   = &ctype{simple: sNonEmpty}
	tURI        = &ctype{simple: sURI}
	tDateTime   = &ctype{simple: sDateTime}
	tBase64     = &ctype{simple: sBase64}
	tMultiLang  = &ctype{simple: sNonEmpty, lang: true}
	tMultiURI   = &ctype{simple: sURI, lang: true}
	tAny        = &ctype{any: true}
	tExtension  = &ctype{any: true, Attrs: map[string]bool{"Critical": true}}
	tIntNames   = &ctype{seq: []particle{el("Name", 1, -1, tMultiLang)}}
	tURIList    = &ctype{seq: []particle{el("URI", 1, -1, tURI)}}
	tMultiURIs  = &ctype{seq: []particle{el("URI", 1, -1, tMultiURI)}}
	tExtensions = &ctype{seq: []particle{el("Extension", 1, -1, tExtension)}}
	tAddress    = &ctype{seq: []particle{
		el("PostalAddresses", 1, 1, &ctype{seq: []particle{
			el("PostalAddress", 1, -1, &ctype{lang: true, seq: []particle{
				el("StreetAddress", 1, 1, tNonEmpty),
				el("Locality", 1, 1, tNonEmpty),
				el("StateOrProvince", 0, 1, tNonEmpty),
				el("PostalCode", 0, 1, tNonEmpty),
				el("CountryName", 1, 1, tNonEmpty),
			}}),
		}}),
		el("ElectronicAddress", 1, 1, tURIList),
	}}
	tDigitalIdentity = &ctype{seq: []particle{
		el("DigitalId", 0, -1, &ctype{choice: true, choiceMin: 1, choiceMax: 1, seq: []particle{
			el("X509Certificate", 1, 1, tBase64),
			el("X509SubjectName", 1, 1, tString),
			{xmldsig.NSDSig, "KeyValue", 1, 1, tAny},
			el("X509SKI", 1, 1, tBase64),
			el("Other", 1, 1, tAny),
		}}),
	}}
	tServiceInformation = &ctype{seq: []particle{
		el("ServiceTypeIdentifier", 1, 1, tURI),
		el("ServiceName", 1, 1, tIntNames),
		el("ServiceDigitalIdentity", 1, 1, tDigitalIdentity),
		el("ServiceStatus", 1, 1, tURI),
		el("StatusStartingTime", 1, 1, tDateTime),
		el("SchemeServiceDefinitionURI", 0, 1, tMultiURIs),
		el("ServiceSupplyPoints", 0, 1, &ctype{seq: []particle{el("ServiceSupplyPoint", 1, -1, tURI)}}),
		el("TSPServiceDefinitionURI", 0, 1, tMultiURIs),
		el("ServiceInformationExtensions", 0, 1, tExtensions),
	}}
	tServiceHistory = &ctype{seq: []particle{
		el("ServiceHistoryInstance", 0, -1, &ctype{seq: []particle{
			el("ServiceTypeIdentifier", 1, 1, tURI),
			el("ServiceName", 1, 1, tIntNames),
			el("ServiceDigitalIdentity", 1, 1, tDigitalIdentity),
			el("ServiceStatus", 1, 1, tURI),
			el("StatusStartingTime", 1, 1, tDateTime),
			el("ServiceInformationExtensions", 0, 1, tExtensions),
		}}),
	}}
	tSchemeInformation = &ctype{seq: []particle{
		el("TSLVersionIdentifier", 1, 1, &ctype{simple: sInteger}),
		el("TSLSequenceNumber", 1, 1, &ctype{simple: sPositive}),
		el("TSLType", 1, 1, tURI),
		el("SchemeOperatorName", 1, 1, tIntNames),
		el("SchemeOperatorAddress", 1, 1, tAddress),
		el("SchemeName", 1, 1, tIntNames),
		el("SchemeInformationURI", 1, 1, tMultiURIs),
		el("StatusDeterminationApproach", 1, 1, tURI),
		el("SchemeTypeCommunityRules", 0, 1, tURIList),
		el("SchemeTerritory", 0, 1, &ctype{simple: sTerritory}),
		el("PolicyOrLegalNotice", 0, 1, &ctype{choice: true, uniform: true, choiceMin: 1, choiceMax: -1, seq: []particle{
			el("TSLPolicy", 1, 1, tMultiURI),
			el("TSLLegalNotice", 1, 1, tMultiLang),
		}}),
		el("HistoricalInformationPeriod", 1, 1, &ctype{simple: sNonNegative}),
		el("PointersToOtherTSL", 0, 1, &ctype{seq: []particle{
			el("OtherTSLPointer", 1, -1, &ctype{seq: []particle{
				el("ServiceDigitalIdentities", 0, 1, &ctype{seq: []particle{el("ServiceDigitalIdentity", 1, -1, tDigitalIdentity)}}),
				el("TSLLocation", 1, 1, tURI),
				el("AdditionalInformation", 0, 1, &ctype{choice: true, choiceMin: 1, choiceMax: -1, seq: []particle{
					el("TextualInformation", 1, 1, tMultiLang),
					el("OtherInformation", 1, 1, tAny),
				}}),
			}}),
		}}),
		el("ListIssueDateTime", 1, 1, tDateTime),
		el("NextUpdate", 1, 1, &ctype{seq: []particle{el("dateTime", 0, 1, tDateTime)}}),
		el("DistributionPoints", 0, 1, tURIList),
		el("SchemeExtensions", 0, 1, tExtensions),
	}}
	tTSPInformation = &ctype{seq: []particle{
		el("TSPName", 1, 1, tIntNames),
		el("TSPTradeName", 0, 1, tIntNames),
		el("TSPAddress", 1, 1, tAddress),
		el("TSPInformationURI", 1, 1, tMultiURIs),
		el("TSPInformationExtensions", 0, 1, tExtensions),
	}}
	tTrustStatusList = &ctype{
		Attrs: map[string]bool{"TSLTag": true, "Id": false},
		seq: []particle{
			el("SchemeInformation", 1, 1, tSchemeInformation),
			el("TrustServiceProviderList", 0, 1, &ctype{seq: []particle{
				el("TrustServiceProvider", 1, -1, &ctype{seq: []particle{
					el("TSPInformation", 1, 1, tTSPInformation),
					el("TSPServices", 1, 1, &ctype{seq: []particle{
						el("TSPService", 1, -1, &ctype{seq: []particle{
							el("ServiceInformation", 1, 1, tServiceInformation),
							el("ServiceHistory", 0, 1, tServiceHistory),
						}}),
					}}),
				}}),
			}}),
			{xmldsig.NSDSig, "Signature", 0, 1, tAny},
		},
	}
)

// checkSchema checks doc against the TSL schema.
func checkSchema(doc *xmldsig.Document) error {
	r := doc.Root
	if !r.Is(nsTSL, "TrustServiceStatusList") {
		return fmt.Errorf("tsl: schema: root element {%s}%s is not a TrustServiceStatusList", r.Space, r.Local)
	}
	if v, _ := r.Attr("TSLTag"); v != "http://uri.etsi.org/02231/TSLTag" {
		return fmt.Errorf("tsl: schema: bad TSLTag %q", v)
	}
	return checkElement(r, tTrustStatusList)
}

func checkElement(e *xmldsig.Element, t *ctype) error {
	if err := checkAttrs(e, t); err != nil {
		return err
	}
	if t.any {
		return nil
	}
	kids := e.Children()
	if t.simple != sNone {
		if len(kids) > 0 {
			return fmt.Errorf("tsl: schema: element %s has child elements", e.Local)
		}
		return checkSimple(e, t.simple)
	}
	if strings.TrimSpace(e.Text()) != "" {
		return fmt.Errorf("tsl: schema: element %s has text content", e.Local)
	}
	if t.choice {
		return checkChoice(e, kids, t)
	}
	i := 0
	for _, p := range t.seq {
		n := 0
		for i < len(kids) && kids[i].Is(p.Space, p.Local) {
			if p.max >= 0 && n == p.max {
				return fmt.Errorf("tsl: schema: too many %s in %s", p.Local, e.Local)
			}
			if err := checkElement(kids[i], p.typ); err != nil {
				return err
			}
			i++
			n++
		}
		if n < p.min {
			return fmt.Errorf("tsl: schema: %s lacks %s", e.Local, p.Local)
		}
	}
	if i < len(kids) {
		return fmt.Errorf("tsl: schema: unexpected element {%s}%s in %s", kids[i].Space, kids[i].Local, e.Local)
	}
	return nil
}

func checkChoice(e *xmldsig.Element, kids []*xmldsig.Element, t *ctype) error {
	if len(kids) < t.choiceMin || t.choiceMax >= 0 && len(kids) > t.choiceMax {
		return fmt.Errorf("tsl: schema: %s has %d children", e.Local, len(kids))
	}
	for _, k := range kids {
		if t.uniform && (k.Space != kids[0].Space || k.Local != kids[0].Local) {
			return fmt.Errorf("tsl: schema: %s mixes %s and %s", e.Local, kids[0].Local, k.Local)
		}
		found := false
		for _, p := range t.seq {
			if k.Is(p.Space, p.Local) {
				if err := checkElement(k, p.typ); err != nil {
					return err
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("tsl: schema: unexpected element {%s}%s in %s", k.Space, k.Local, e.Local)
		}
	}
	return nil
}

func checkAttrs(e *xmldsig.Element, t *ctype) error {
	if t.lang {
		if v, ok := xmlLang(e); !ok || v == "" {
			return fmt.Errorf("tsl: schema: %s lacks xml:lang", e.Local)
		}
	}
	for name, required := range t.Attrs {
		if _, ok := e.Attr(name); required && !ok {
			return fmt.Errorf("tsl: schema: %s lacks attribute %s", e.Local, name)
		}
	}
	if t.any && t.Attrs == nil {
		return nil
	}
	for _, a := range e.Attrs {
		switch {
		case a.Space == xmldsig.NSXML && a.Local == "lang" && t.lang:
		case a.Space == "" && t.Attrs != nil:
			if _, ok := t.Attrs[a.Local]; !ok {
				return fmt.Errorf("tsl: schema: unexpected attribute %s on %s", a.Local, e.Local)
			}
		default:
			return fmt.Errorf("tsl: schema: unexpected attribute %s on %s", a.Local, e.Local)
		}
	}
	if v, ok := e.Attr("Critical"); ok && v != "true" && v != "false" && v != "1" && v != "0" {
		return fmt.Errorf("tsl: schema: bad Critical value %q", v)
	}
	return nil
}

func xmlLang(e *xmldsig.Element) (string, bool) {
	for _, a := range e.Attrs {
		if a.Space == xmldsig.NSXML && a.Local == "lang" {
			return a.Value, true
		}
	}
	return "", false
}

// collapse applies the whitespace facet "collapse" of XML Schema.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

func checkSimple(e *xmldsig.Element, k simpleKind) error {
	v := e.Text()
	bad := func() error { return fmt.Errorf("tsl: schema: bad value %q in %s", v, e.Local) }
	switch k {
	case sNonEmpty:
		if v == "" {
			return bad()
		}
	case sURI:
		if collapse(v) == "" {
			return bad()
		}
	case sInteger, sPositive, sNonNegative:
		n, ok := new(big.Int).SetString(collapse(v), 10)
		if !ok || k == sPositive && n.Sign() <= 0 || k == sNonNegative && n.Sign() < 0 {
			return bad()
		}
	case sDateTime:
		if _, err := parseDateTime(v); err != nil {
			return bad()
		}
	case sBase64:
		if _, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v), "")); err != nil {
			return bad()
		}
	case sTerritory:
		if len([]rune(v)) != 2 {
			return bad()
		}
	}
	return nil
}

// parseDateTime parses an xsd:dateTime. A value without time zone is
// taken as UTC.
func parseDateTime(s string) (time.Time, error) {
	s = collapse(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("tsl: bad dateTime %q", s)
}
