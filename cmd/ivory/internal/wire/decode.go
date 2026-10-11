package wire

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// HexBytes is a byte string that marshals as hex.
type HexBytes []byte

// MarshalText returns the hex encoding of b.
func (b HexBytes) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(b)), nil }

// An Extension is a raw TLS extension.
type Extension struct {
	Type   ExtensionType `json:"type"`
	Length int           `json:"length"`
	Data   HexBytes      `json:"data,omitempty"`
}

var errMalformed = errors.New("malformed message")

func readExtensions(s *cryptobyte.String) ([]Extension, error) {
	if s.Empty() {
		return nil, nil
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return nil, errMalformed
	}
	var out []Extension
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, errMalformed
		}
		out = append(out, Extension{Type: ExtensionType(typ), Length: len(data), Data: HexBytes(data)})
	}
	return out, nil
}

func findExtension(exts []Extension, t ExtensionType) *Extension {
	for i := range exts {
		if exts[i].Type == t {
			return &exts[i]
		}
	}
	return nil
}

func readUint16List(data []byte, prefixLen int) []uint16 {
	s := cryptobyte.String(data)
	var list cryptobyte.String
	var ok bool
	switch prefixLen {
	case 1:
		ok = s.ReadUint8LengthPrefixed(&list)
	default:
		ok = s.ReadUint16LengthPrefixed(&list)
	}
	if !ok {
		return nil
	}
	var out []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return out
		}
		out = append(out, v)
	}
	return out
}

func groups(v []uint16) []Group {
	out := make([]Group, len(v))
	for i, x := range v {
		out[i] = Group(x)
	}
	return out
}

func schemes(v []uint16) []SignatureScheme {
	out := make([]SignatureScheme, len(v))
	for i, x := range v {
		out[i] = SignatureScheme(x)
	}
	return out
}

func readALPN(data []byte) []string {
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return nil
	}
	var out []string
	for !list.Empty() {
		var p cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&p) {
			return out
		}
		out = append(out, string(p))
	}
	return out
}

// A ClientHello is a decoded ClientHello message.
type ClientHello struct {
	Version      Version       `json:"legacy_version"`
	Random       HexBytes      `json:"random"`
	SessionID    HexBytes      `json:"session_id,omitempty"`
	CipherSuites []CipherSuite `json:"cipher_suites"`
	Compression  []uint8       `json:"compression_methods"`
	Extensions   []Extension   `json:"extensions"`

	// Decoded extensions.
	ServerName              string            `json:"server_name,omitempty"`
	SupportedVersions       []Version         `json:"supported_versions,omitempty"`
	SupportedGroups         []Group           `json:"supported_groups,omitempty"`
	KeyShares               []Group           `json:"key_shares,omitempty"`
	ECPointFormats          []uint8           `json:"ec_point_formats,omitempty"`
	SignatureAlgorithms     []SignatureScheme `json:"signature_algorithms,omitempty"`
	SignatureAlgorithmsCert []SignatureScheme `json:"signature_algorithms_cert,omitempty"`
	ALPN                    []string          `json:"alpn,omitempty"`
	PSKModes                []uint8           `json:"psk_key_exchange_modes,omitempty"`
}

// Has reports whether the ClientHello carries extension t.
func (ch *ClientHello) Has(t ExtensionType) bool { return findExtension(ch.Extensions, t) != nil }

// ParseClientHello decodes a ClientHello body.
func ParseClientHello(body []byte) (*ClientHello, error) {
	s := cryptobyte.String(body)
	ch := &ClientHello{}
	var v uint16
	var random, sid, suites, comp cryptobyte.String
	if !s.ReadUint16(&v) || !s.ReadBytes((*[]byte)(&random), 32) || !s.ReadUint8LengthPrefixed(&sid) ||
		!s.ReadUint16LengthPrefixed(&suites) || !s.ReadUint8LengthPrefixed(&comp) {
		return nil, errMalformed
	}
	ch.Version, ch.Random, ch.SessionID = Version(v), HexBytes(random), HexBytes(sid)
	for !suites.Empty() {
		var c uint16
		if !suites.ReadUint16(&c) {
			return nil, errMalformed
		}
		ch.CipherSuites = append(ch.CipherSuites, CipherSuite(c))
	}
	ch.Compression = append([]uint8{}, comp...)
	exts, err := readExtensions(&s)
	if err != nil {
		return nil, err
	}
	ch.Extensions = exts
	for _, e := range exts {
		switch e.Type {
		case ExtServerName:
			ch.ServerName = parseServerName(e.Data)
		case ExtSupportedVersions:
			d := cryptobyte.String(e.Data)
			var list cryptobyte.String
			if d.ReadUint8LengthPrefixed(&list) {
				for !list.Empty() {
					var x uint16
					if !list.ReadUint16(&x) {
						break
					}
					ch.SupportedVersions = append(ch.SupportedVersions, Version(x))
				}
			}
		case ExtSupportedGroups:
			ch.SupportedGroups = groups(readUint16List(e.Data, 2))
		case ExtKeyShare:
			d := cryptobyte.String(e.Data)
			var list cryptobyte.String
			if d.ReadUint16LengthPrefixed(&list) {
				for !list.Empty() {
					var g uint16
					var kx cryptobyte.String
					if !list.ReadUint16(&g) || !list.ReadUint16LengthPrefixed(&kx) {
						break
					}
					ch.KeyShares = append(ch.KeyShares, Group(g))
				}
			}
		case ExtECPointFormats:
			d := cryptobyte.String(e.Data)
			var list cryptobyte.String
			if d.ReadUint8LengthPrefixed(&list) {
				ch.ECPointFormats = append([]uint8{}, list...)
			}
		case ExtSignatureAlgorithms:
			ch.SignatureAlgorithms = schemes(readUint16List(e.Data, 2))
		case ExtSignatureAlgorithmsCert:
			ch.SignatureAlgorithmsCert = schemes(readUint16List(e.Data, 2))
		case ExtALPN:
			ch.ALPN = readALPN(e.Data)
		case ExtPSKModes:
			d := cryptobyte.String(e.Data)
			var list cryptobyte.String
			if d.ReadUint8LengthPrefixed(&list) {
				ch.PSKModes = append([]uint8{}, list...)
			}
		}
	}
	return ch, nil
}

func parseServerName(data []byte) string {
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return ""
	}
	for !list.Empty() {
		var typ uint8
		var name cryptobyte.String
		if !list.ReadUint8(&typ) || !list.ReadUint16LengthPrefixed(&name) {
			return ""
		}
		if typ == 0 {
			return string(name)
		}
	}
	return ""
}

// helloRetryRandom is the Random of a HelloRetryRequest (RFC 8446,
// Section 4.1.3).
var helloRetryRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// A ServerHello is a decoded ServerHello or HelloRetryRequest.
type ServerHello struct {
	Version     Version     `json:"legacy_version"`
	Random      HexBytes    `json:"random"`
	SessionID   HexBytes    `json:"session_id,omitempty"`
	CipherSuite CipherSuite `json:"cipher_suite"`
	Compression uint8       `json:"compression_method"`
	Extensions  []Extension `json:"extensions"`

	HelloRetryRequest bool `json:"hello_retry_request,omitempty"`
	// SupportedVersion is the selected_version of supported_versions, or 0.
	SupportedVersion Version `json:"supported_version,omitempty"`
	// KeyShare is the group of the key_share (the selected_group of a
	// HelloRetryRequest), or 0.
	KeyShare Group  `json:"key_share,omitempty"`
	ALPN     string `json:"alpn,omitempty"`
	// Downgrade is the version that the downgrade sentinel in Random
	// names (RFC 8446, Section 4.1.3): "TLS 1.2" or "TLS 1.1", or "".
	Downgrade string `json:"downgrade_sentinel,omitempty"`
}

// Has reports whether the ServerHello carries extension t.
func (sh *ServerHello) Has(t ExtensionType) bool { return findExtension(sh.Extensions, t) != nil }

// Negotiated returns the version the server selected.
func (sh *ServerHello) Negotiated() Version {
	if sh.SupportedVersion != 0 {
		return sh.SupportedVersion
	}
	return sh.Version
}

// ParseServerHello decodes a ServerHello body.
func ParseServerHello(body []byte) (*ServerHello, error) {
	s := cryptobyte.String(body)
	sh := &ServerHello{}
	var v, suite uint16
	var random, sid cryptobyte.String
	if !s.ReadUint16(&v) || !s.ReadBytes((*[]byte)(&random), 32) || !s.ReadUint8LengthPrefixed(&sid) ||
		!s.ReadUint16(&suite) || !s.ReadUint8(&sh.Compression) {
		return nil, errMalformed
	}
	sh.Version, sh.Random, sh.SessionID, sh.CipherSuite = Version(v), HexBytes(random), HexBytes(sid), CipherSuite(suite)
	sh.HelloRetryRequest = bytes.Equal(random, helloRetryRandom)
	switch tail := random[24:]; {
	case bytes.Equal(tail, []byte("DOWNGRD\x01")):
		sh.Downgrade = "TLS 1.2"
	case bytes.Equal(tail, []byte("DOWNGRD\x00")):
		sh.Downgrade = "TLS 1.1"
	}
	exts, err := readExtensions(&s)
	if err != nil {
		return nil, err
	}
	sh.Extensions = exts
	for _, e := range exts {
		switch e.Type {
		case ExtSupportedVersions:
			if len(e.Data) == 2 {
				sh.SupportedVersion = Version(uint16(e.Data[0])<<8 | uint16(e.Data[1]))
			}
		case ExtKeyShare:
			if len(e.Data) >= 2 {
				sh.KeyShare = Group(uint16(e.Data[0])<<8 | uint16(e.Data[1]))
			}
		case ExtALPN:
			if p := readALPN(e.Data); len(p) == 1 {
				sh.ALPN = p[0]
			}
		}
	}
	return sh, nil
}

// ParseCertificate decodes a TLS 1.2 Certificate body (tls13 false) or a
// TLS 1.3 one, and returns the DER certificates.
func ParseCertificate(body []byte, tls13 bool) ([][]byte, error) {
	s := cryptobyte.String(body)
	if tls13 {
		var ctx cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&ctx) {
			return nil, errMalformed
		}
	}
	var list cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&list) {
		return nil, errMalformed
	}
	var out [][]byte
	for !list.Empty() {
		var cert cryptobyte.String
		if !list.ReadUint24LengthPrefixed(&cert) {
			return nil, errMalformed
		}
		out = append(out, append([]byte(nil), cert...))
		if tls13 {
			var exts cryptobyte.String
			if !list.ReadUint16LengthPrefixed(&exts) {
				return nil, errMalformed
			}
		}
	}
	return out, nil
}

// A ServerKeyExchange is a decoded TLS 1.2 (or older) ServerKeyExchange.
type ServerKeyExchange struct {
	// Kind is "ECDHE" or "DHE".
	Kind string `json:"kind"`
	// Group is the named curve of an ECDHE exchange.
	Group Group `json:"group,omitempty"`
	// DHBits is the size of the DHE prime in bits.
	DHBits          int             `json:"dh_bits,omitempty"`
	PublicKeyLength int             `json:"public_key_length"`
	SignatureScheme SignatureScheme `json:"signature_scheme,omitempty"`
	SignatureLength int             `json:"signature_length"`
}

// ParseServerKeyExchange decodes an ECDHE or DHE ServerKeyExchange. With
// version below TLS 1.2, the signature has no scheme.
func ParseServerKeyExchange(body []byte, version Version) (*ServerKeyExchange, error) {
	if ske, err := parseECDHE(body, version); err == nil {
		return ske, nil
	}
	s := cryptobyte.String(body)
	var p, g, y cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&p) || !s.ReadUint16LengthPrefixed(&g) || !s.ReadUint16LengthPrefixed(&y) {
		return nil, errMalformed
	}
	p = bytes.TrimLeft(p, "\x00")
	ske := &ServerKeyExchange{Kind: "DHE", PublicKeyLength: len(y)}
	if len(p) > 0 {
		ske.DHBits = (len(p)-1)*8 + bitLen(p[0])
	}
	if err := readSignature(&s, version, ske); err != nil {
		return nil, err
	}
	return ske, nil
}

func bitLen(b byte) int {
	n := 0
	for ; b != 0; b >>= 1 {
		n++
	}
	return n
}

func parseECDHE(body []byte, version Version) (*ServerKeyExchange, error) {
	s := cryptobyte.String(body)
	var curveType uint8
	var group uint16
	var point cryptobyte.String
	if !s.ReadUint8(&curveType) || curveType != 3 || !s.ReadUint16(&group) || !s.ReadUint8LengthPrefixed(&point) {
		return nil, errMalformed
	}
	ske := &ServerKeyExchange{Kind: "ECDHE", Group: Group(group), PublicKeyLength: len(point)}
	if err := readSignature(&s, version, ske); err != nil {
		return nil, err
	}
	return ske, nil
}

func readSignature(s *cryptobyte.String, version Version, ske *ServerKeyExchange) error {
	if version >= VersionTLS12 || version == 0 {
		var scheme uint16
		if !s.ReadUint16(&scheme) {
			return errMalformed
		}
		ske.SignatureScheme = SignatureScheme(scheme)
	}
	var sig cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&sig) || !s.Empty() {
		return errMalformed
	}
	ske.SignatureLength = len(sig)
	return nil
}

// A CertificateRequest is a decoded TLS 1.2 (or older) CertificateRequest.
type CertificateRequest struct {
	CertificateTypes    []uint8           `json:"certificate_types"`
	SignatureAlgorithms []SignatureScheme `json:"signature_algorithms,omitempty"`
	// CAs are the certificate_authorities as DER distinguished names.
	CAs []HexBytes `json:"-"`
	// CANames are CAs as strings.
	CANames []string `json:"certificate_authorities"`
}

// ParseCertificateRequest decodes a TLS 1.2 (or older) CertificateRequest.
func ParseCertificateRequest(body []byte, version Version) (*CertificateRequest, error) {
	s := cryptobyte.String(body)
	cr := &CertificateRequest{CANames: []string{}}
	var types, cas cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&types) {
		return nil, errMalformed
	}
	cr.CertificateTypes = append([]uint8{}, types...)
	if version >= VersionTLS12 || version == 0 {
		var algs cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&algs) {
			return nil, errMalformed
		}
		for !algs.Empty() {
			var a uint16
			if !algs.ReadUint16(&a) {
				return nil, errMalformed
			}
			cr.SignatureAlgorithms = append(cr.SignatureAlgorithms, SignatureScheme(a))
		}
	}
	if !s.ReadUint16LengthPrefixed(&cas) || !s.Empty() {
		return nil, errMalformed
	}
	for !cas.Empty() {
		var dn cryptobyte.String
		if !cas.ReadUint16LengthPrefixed(&dn) {
			return nil, errMalformed
		}
		cr.CAs = append(cr.CAs, HexBytes(append([]byte(nil), dn...)))
		cr.CANames = append(cr.CANames, DNString(dn))
	}
	return cr, nil
}

// DNString formats a DER distinguished name, or returns its hex form if it
// doesn't parse.
func DNString(der []byte) string {
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdn); err != nil || len(rest) > 0 {
		return "0x" + hex.EncodeToString(der)
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdn)
	return n.String()
}

// CertificateTypeName names a ClientCertificateType (RFC 5246, RFC 8422).
func CertificateTypeName(t uint8) string {
	switch t {
	case 1:
		return "rsa_sign"
	case 2:
		return "dss_sign"
	case 3:
		return "rsa_fixed_dh"
	case 4:
		return "dss_fixed_dh"
	case 64:
		return "ecdsa_sign"
	case 65:
		return "rsa_fixed_ecdh"
	case 66:
		return "ecdsa_fixed_ecdh"
	}
	return fmt.Sprintf("type(%d)", t)
}

// A CertificateStatus is a decoded CertificateStatus (OCSP stapling).
type CertificateStatus struct {
	StatusType     uint8 `json:"status_type"`
	ResponseLength int   `json:"response_length"`
	Response       []byte
}

// ParseCertificateStatus decodes a CertificateStatus body.
func ParseCertificateStatus(body []byte) (*CertificateStatus, error) {
	s := cryptobyte.String(body)
	cs := &CertificateStatus{}
	var resp cryptobyte.String
	if !s.ReadUint8(&cs.StatusType) || !s.ReadUint24LengthPrefixed(&resp) {
		return nil, errMalformed
	}
	cs.ResponseLength, cs.Response = len(resp), append([]byte(nil), resp...)
	return cs, nil
}

// Describe returns a human-readable description of a handshake message in
// a few lines. version is the negotiated version, or 0 if not known yet.
func Describe(m Message, version Version) []string {
	var lines []string
	add := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	switch m.Type {
	case TypeClientHello:
		ch, err := ParseClientHello(m.Body)
		if err != nil {
			add("(%v)", err)
			break
		}
		add("legacy_version %v, session_id %d bytes, compression %v", ch.Version, len(ch.SessionID), ch.Compression)
		add("cipher_suites %s", joinStrings(ch.CipherSuites))
		add("extensions %s", extensionList(ch.Extensions))
		if ch.ServerName != "" {
			add("server_name %s", ch.ServerName)
		}
		if ch.SupportedVersions != nil {
			add("supported_versions %s", joinStrings(ch.SupportedVersions))
		}
		if ch.SupportedGroups != nil {
			add("supported_groups %s", joinStrings(ch.SupportedGroups))
		}
		if ch.Has(ExtKeyShare) {
			add("key_share %s", joinStrings(ch.KeyShares))
		}
		if ch.ECPointFormats != nil {
			add("ec_point_formats %v", ch.ECPointFormats)
		}
		if ch.SignatureAlgorithms != nil {
			add("signature_algorithms %s", joinStrings(ch.SignatureAlgorithms))
		}
		if ch.SignatureAlgorithmsCert != nil {
			add("signature_algorithms_cert %s", joinStrings(ch.SignatureAlgorithmsCert))
		}
		if ch.ALPN != nil {
			add("alpn %s", strings.Join(ch.ALPN, ", "))
		}
	case TypeServerHello:
		sh, err := ParseServerHello(m.Body)
		if err != nil {
			add("(%v)", err)
			break
		}
		if sh.HelloRetryRequest {
			add("HelloRetryRequest")
		}
		add("legacy_version %v, cipher_suite %v, compression %d, session_id %d bytes", sh.Version, sh.CipherSuite, sh.Compression, len(sh.SessionID))
		add("extensions %s", extensionList(sh.Extensions))
		if sh.SupportedVersion != 0 {
			add("supported_versions %v", sh.SupportedVersion)
		}
		if sh.KeyShare != 0 {
			add("key_share %v", sh.KeyShare)
		}
		if sh.ALPN != "" {
			add("alpn %s", sh.ALPN)
		}
		if sh.Downgrade != "" {
			add("downgrade sentinel for %s", sh.Downgrade)
		}
	case TypeCertificate:
		certs, err := ParseCertificate(m.Body, version == VersionTLS13)
		if err != nil {
			add("(%v)", err)
			break
		}
		add("%d certificates", len(certs))
		for i, der := range certs {
			add("[%d] %s", i, certSummary(der))
		}
	case TypeServerKeyExchange:
		ske, err := ParseServerKeyExchange(m.Body, version)
		if err != nil {
			add("(%v)", err)
			break
		}
		if ske.Kind == "ECDHE" {
			add("ECDHE group %v, public key %d bytes", ske.Group, ske.PublicKeyLength)
		} else {
			add("DHE %d-bit prime, public key %d bytes", ske.DHBits, ske.PublicKeyLength)
		}
		if ske.SignatureScheme != 0 {
			add("signature %v, %d bytes", ske.SignatureScheme, ske.SignatureLength)
		} else {
			add("signature %d bytes", ske.SignatureLength)
		}
	case TypeCertificateRequest:
		if version == VersionTLS13 {
			add("%d bytes", len(m.Body))
			break
		}
		cr, err := ParseCertificateRequest(m.Body, version)
		if err != nil {
			add("(%v)", err)
			break
		}
		var types []string
		for _, t := range cr.CertificateTypes {
			types = append(types, CertificateTypeName(t))
		}
		add("certificate_types %s", strings.Join(types, ", "))
		if cr.SignatureAlgorithms != nil {
			add("signature_algorithms %s", joinStrings(cr.SignatureAlgorithms))
		}
		add("certificate_authorities: %d", len(cr.CANames))
		for _, n := range cr.CANames {
			add("  %s", n)
		}
	case TypeCertificateStatus:
		cs, err := ParseCertificateStatus(m.Body)
		if err != nil {
			add("(%v)", err)
			break
		}
		add("status_type %d, OCSP response %d bytes", cs.StatusType, cs.ResponseLength)
	case TypeClientKeyExchange:
		add("%d bytes", len(m.Body))
	case TypeCertificateVerify:
		if len(m.Body) >= 2 && version != VersionTLS10 && version != VersionTLS11 {
			add("signature %v", SignatureScheme(uint16(m.Body[0])<<8|uint16(m.Body[1])))
		} else {
			add("%d bytes", len(m.Body))
		}
	case TypeNewSessionTicket:
		if len(m.Body) >= 4 {
			add("lifetime %d s, %d bytes", uint32(m.Body[0])<<24|uint32(m.Body[1])<<16|uint32(m.Body[2])<<8|uint32(m.Body[3]), len(m.Body))
		}
	default:
		add("%d bytes", len(m.Body))
	}
	return lines
}

func joinStrings[T fmt.Stringer](v []T) string {
	if len(v) == 0 {
		return "(none)"
	}
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = x.String()
	}
	return strings.Join(s, ", ")
}

func extensionList(exts []Extension) string {
	if len(exts) == 0 {
		return "(none)"
	}
	s := make([]string, len(exts))
	for i, e := range exts {
		s[i] = e.Type.Name()
	}
	return strings.Join(s, ", ")
}

// certSummary returns the subject and issuer of a DER certificate without
// parsing its key, so that it works for every key type.
func certSummary(der []byte) string {
	var cert struct {
		TBS struct {
			Raw          asn1.RawContent
			Version      int `asn1:"optional,explicit,default:0,tag:0"`
			SerialNumber asn1.RawValue
			SigAlg       asn1.RawValue
			Issuer       asn1.RawValue
			Validity     asn1.RawValue
			Subject      asn1.RawValue
		}
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return fmt.Sprintf("%d bytes (%v)", len(der), err)
	}
	return fmt.Sprintf("subject %q, issuer %q", DNString(cert.TBS.Subject.FullBytes), DNString(cert.TBS.Issuer.FullBytes))
}

// UnmarshalText parses the hex encoding of MarshalText.
func (b *HexBytes) UnmarshalText(text []byte) error {
	v, err := hex.DecodeString(string(text))
	*b = v
	return err
}
