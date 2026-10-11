package wire

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a TLS protocol version.
type Version uint16

// Protocol versions.
const (
	VersionSSL30 Version = 0x0300
	VersionTLS10 Version = 0x0301
	VersionTLS11 Version = 0x0302
	VersionTLS12 Version = 0x0303
	VersionTLS13 Version = 0x0304
)

func (v Version) String() string {
	switch v {
	case VersionSSL30:
		return "SSL 3.0"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	}
	if IsGREASE(uint16(v)) {
		return fmt.Sprintf("GREASE(0x%04x)", uint16(v))
	}
	return fmt.Sprintf("0x%04x", uint16(v))
}

// MarshalText returns String.
func (v Version) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// IsGREASE reports whether v is a GREASE value (RFC 8701).
func IsGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// named formats a code point as "name(0x....)" or as hex if unnamed.
func named(names map[uint16]string, v uint16) string {
	if n, ok := names[v]; ok {
		return fmt.Sprintf("%s(0x%04x)", n, v)
	}
	if IsGREASE(v) {
		return fmt.Sprintf("GREASE(0x%04x)", v)
	}
	return fmt.Sprintf("0x%04x", v)
}

// Name returns the bare name of a code point, or its hex value.
func name(names map[uint16]string, v uint16) string {
	if n, ok := names[v]; ok {
		return n
	}
	if IsGREASE(v) {
		return "GREASE"
	}
	return fmt.Sprintf("0x%04x", v)
}

// CipherSuite is a TLS cipher suite.
type CipherSuite uint16

func (s CipherSuite) String() string { return named(suiteNames, uint16(s)) }

// Name returns the IANA name of s, or its hex value.
func (s CipherSuite) Name() string { return name(suiteNames, uint16(s)) }

// MarshalText returns String.
func (s CipherSuite) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// IsTLS13 reports whether s is a TLS 1.3 suite.
func (s CipherSuite) IsTLS13() bool { return s>>8 == 0x13 }

// IsECDHE reports whether s uses ECDHE key exchange (TLS 1.2 and older).
func (s CipherSuite) IsECDHE() bool { return strings.HasPrefix(s.Name(), "TLS_ECDHE_") }

// IsDHE reports whether s uses finite-field DHE key exchange.
func (s CipherSuite) IsDHE() bool { return strings.HasPrefix(s.Name(), "TLS_DHE_") }

// IsECDSA reports whether s authenticates the server with ECDSA.
func (s CipherSuite) IsECDSA() bool { return strings.HasPrefix(s.Name(), "TLS_ECDHE_ECDSA_") }

// IsCBC reports whether s uses a block cipher in CBC mode.
func (s CipherSuite) IsCBC() bool { return strings.Contains(s.Name(), "_CBC_") }

// Group is a TLS named group (supported_groups, key_share).
type Group uint16

func (g Group) String() string { return named(groupNames, uint16(g)) }

// Name returns the name of g, or its hex value.
func (g Group) Name() string { return name(groupNames, uint16(g)) }

// MarshalText returns String.
func (g Group) MarshalText() ([]byte, error) { return []byte(g.String()), nil }

// SignatureScheme is a TLS signature scheme (signature_algorithms).
type SignatureScheme uint16

func (s SignatureScheme) String() string { return named(schemeNames, uint16(s)) }

// Name returns the name of s, or its hex value.
func (s SignatureScheme) Name() string { return name(schemeNames, uint16(s)) }

// MarshalText returns String.
func (s SignatureScheme) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ExtensionType is a TLS extension type.
type ExtensionType uint16

func (e ExtensionType) String() string { return named(extensionNames, uint16(e)) }

// Name returns the name of e, or its hex value.
func (e ExtensionType) Name() string { return name(extensionNames, uint16(e)) }

// MarshalText returns String.
func (e ExtensionType) MarshalText() ([]byte, error) { return []byte(e.String()), nil }

// HandshakeType is a TLS handshake message type.
type HandshakeType uint8

// Handshake message types.
const (
	TypeHelloRequest        HandshakeType = 0
	TypeClientHello         HandshakeType = 1
	TypeServerHello         HandshakeType = 2
	TypeNewSessionTicket    HandshakeType = 4
	TypeEncryptedExtensions HandshakeType = 8
	TypeCertificate         HandshakeType = 11
	TypeServerKeyExchange   HandshakeType = 12
	TypeCertificateRequest  HandshakeType = 13
	TypeServerHelloDone     HandshakeType = 14
	TypeCertificateVerify   HandshakeType = 15
	TypeClientKeyExchange   HandshakeType = 16
	TypeFinished            HandshakeType = 20
	TypeCertificateStatus   HandshakeType = 22
	TypeKeyUpdate           HandshakeType = 24
)

var handshakeNames = map[HandshakeType]string{
	TypeHelloRequest:        "HelloRequest",
	TypeClientHello:         "ClientHello",
	TypeServerHello:         "ServerHello",
	TypeNewSessionTicket:    "NewSessionTicket",
	TypeEncryptedExtensions: "EncryptedExtensions",
	TypeCertificate:         "Certificate",
	TypeServerKeyExchange:   "ServerKeyExchange",
	TypeCertificateRequest:  "CertificateRequest",
	TypeServerHelloDone:     "ServerHelloDone",
	TypeCertificateVerify:   "CertificateVerify",
	TypeClientKeyExchange:   "ClientKeyExchange",
	TypeFinished:            "Finished",
	TypeCertificateStatus:   "CertificateStatus",
	TypeKeyUpdate:           "KeyUpdate",
}

func (t HandshakeType) String() string {
	if n, ok := handshakeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("handshake(%d)", uint8(t))
}

// MarshalText returns String.
func (t HandshakeType) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// RecordType is a TLS record content type.
type RecordType uint8

// Record content types.
const (
	RecordChangeCipherSpec RecordType = 20
	RecordAlert            RecordType = 21
	RecordHandshake        RecordType = 22
	RecordApplicationData  RecordType = 23
)

func (t RecordType) String() string {
	switch t {
	case RecordChangeCipherSpec:
		return "change_cipher_spec"
	case RecordAlert:
		return "alert"
	case RecordHandshake:
		return "handshake"
	case RecordApplicationData:
		return "application_data"
	}
	return fmt.Sprintf("record(%d)", uint8(t))
}

// MarshalText returns String.
func (t RecordType) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// AlertDescription is a TLS alert description.
type AlertDescription uint8

// Alert descriptions used by the probes.
const (
	AlertHandshakeFailure      AlertDescription = 40
	AlertProtocolVersion       AlertDescription = 70
	AlertInappropriateFallback AlertDescription = 86
)

var alertNames = map[uint8]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	21:  "decryption_failed",
	22:  "record_overflow",
	30:  "decompression_failure",
	40:  "handshake_failure",
	41:  "no_certificate",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	49:  "access_denied",
	50:  "decode_error",
	51:  "decrypt_error",
	60:  "export_restriction",
	70:  "protocol_version",
	71:  "insufficient_security",
	80:  "internal_error",
	86:  "inappropriate_fallback",
	90:  "user_canceled",
	100: "no_renegotiation",
	109: "missing_extension",
	110: "unsupported_extension",
	111: "certificate_unobtainable",
	112: "unrecognized_name",
	113: "bad_certificate_status_response",
	114: "bad_certificate_hash_value",
	115: "unknown_psk_identity",
	116: "certificate_required",
	120: "no_application_protocol",
	121: "ech_required",
}

func (a AlertDescription) String() string {
	if n, ok := alertNames[uint8(a)]; ok {
		return n
	}
	return fmt.Sprintf("alert(%d)", uint8(a))
}

// MarshalText returns String.
func (a AlertDescription) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// Code points with names. Sources: the IANA TLS parameters registry,
// RFC 7027 and RFC 8734 (Brainpool), RFC 8446.
var suiteNames = map[uint16]string{
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
	0x5600: "TLS_FALLBACK_SCSV",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc09c: "TLS_RSA_WITH_AES_128_CCM",
	0xc09d: "TLS_RSA_WITH_AES_256_CCM",
	0xc09e: "TLS_DHE_RSA_WITH_AES_128_CCM",
	0xc09f: "TLS_DHE_RSA_WITH_AES_256_CCM",
	0xc0ac: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	0xc0ad: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	0xc0ae: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
	0xc0af: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
	0xc048: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
	0xc049: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
	0xc05c: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
	0xc05d: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
	0xc060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
	0xc061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
	0xc072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xc073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xc086: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xc087: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

var groupNames = map[uint16]string{
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",
	0x001a: "brainpoolP256r1",
	0x001b: "brainpoolP384r1",
	0x001c: "brainpoolP512r1",
	0x001d: "x25519",
	0x001e: "x448",
	0x001f: "brainpoolP256r1tls13",
	0x0020: "brainpoolP384r1tls13",
	0x0021: "brainpoolP512r1tls13",
	0x0100: "ffdhe2048",
	0x0101: "ffdhe3072",
	0x0102: "ffdhe4096",
	0x0103: "ffdhe6144",
	0x0104: "ffdhe8192",
	0x0200: "MLKEM512",
	0x0201: "MLKEM768",
	0x0202: "MLKEM1024",
	0x11eb: "SecP256r1MLKEM768",
	0x11ec: "X25519MLKEM768",
	0x11ed: "SecP384r1MLKEM1024",
}

var schemeNames = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0203: "ecdsa_sha1",
	0x0301: "rsa_pkcs1_sha224",
	0x0303: "ecdsa_sha224",
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
	0x081a: "ecdsa_brainpoolP256r1tls13_sha256",
	0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081c: "ecdsa_brainpoolP512r1tls13_sha512",
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",
}

var extensionNames = map[uint16]string{
	0:      "server_name",
	1:      "max_fragment_length",
	5:      "status_request",
	10:     "supported_groups",
	11:     "ec_point_formats",
	13:     "signature_algorithms",
	14:     "use_srtp",
	15:     "heartbeat",
	16:     "application_layer_protocol_negotiation",
	17:     "status_request_v2",
	18:     "signed_certificate_timestamp",
	21:     "padding",
	22:     "encrypt_then_mac",
	23:     "extended_master_secret",
	27:     "compress_certificate",
	28:     "record_size_limit",
	35:     "session_ticket",
	41:     "pre_shared_key",
	42:     "early_data",
	43:     "supported_versions",
	44:     "cookie",
	45:     "psk_key_exchange_modes",
	47:     "certificate_authorities",
	48:     "oid_filters",
	49:     "post_handshake_auth",
	50:     "signature_algorithms_cert",
	51:     "key_share",
	57:     "quic_transport_parameters",
	17513:  "application_settings",
	0xfe0d: "encrypted_client_hello",
	0xff01: "renegotiation_info",
}

// Extension types used by this package.
const (
	ExtServerName              ExtensionType = 0
	ExtMaxFragmentLength       ExtensionType = 1
	ExtStatusRequest           ExtensionType = 5
	ExtSupportedGroups         ExtensionType = 10
	ExtECPointFormats          ExtensionType = 11
	ExtSignatureAlgorithms     ExtensionType = 13
	ExtHeartbeat               ExtensionType = 15
	ExtALPN                    ExtensionType = 16
	ExtSCT                     ExtensionType = 18
	ExtEncryptThenMAC          ExtensionType = 22
	ExtExtendedMasterSecret    ExtensionType = 23
	ExtRecordSizeLimit         ExtensionType = 28
	ExtSessionTicket           ExtensionType = 35
	ExtSupportedVersions       ExtensionType = 43
	ExtCookie                  ExtensionType = 44
	ExtPSKModes                ExtensionType = 45
	ExtCertificateAuthorities  ExtensionType = 47
	ExtSignatureAlgorithmsCert ExtensionType = 50
	ExtKeyShare                ExtensionType = 51
	ExtRenegotiationInfo       ExtensionType = 0xff01
)

// AllSuites returns every cipher suite with a name in this package, TLS 1.3
// suites and signaling values excluded.
func AllSuites() []CipherSuite {
	var out []CipherSuite
	for v := range suiteNames {
		s := CipherSuite(v)
		if s.IsTLS13() || v == 0x00ff || v == 0x5600 {
			continue
		}
		out = append(out, s)
	}
	sortSuites(out)
	return out
}

// TLS13Suites returns the TLS 1.3 cipher suites of RFC 8446.
func TLS13Suites() []CipherSuite {
	return []CipherSuite{0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
}

// sortSuites orders suites the way a modern client would offer them:
// AEAD with ECDHE first, then the rest, each by code point.
func sortSuites(s []CipherSuite) {
	rank := func(c CipherSuite) int {
		n := c.Name()
		r := 0
		switch {
		case strings.HasPrefix(n, "TLS_ECDHE_"):
		case strings.HasPrefix(n, "TLS_DHE_"):
			r += 10
		default:
			r += 20
		}
		if c.IsCBC() || strings.Contains(n, "RC4") {
			r += 5
		}
		return r
	}
	for i := 1; i < len(s); i++ {
		for j := i; j > 0; j-- {
			a, b := s[j-1], s[j]
			if rank(a) < rank(b) || rank(a) == rank(b) && a < b {
				break
			}
			s[j-1], s[j] = b, a
		}
	}
}

// lookup finds a code point by name (case-insensitive, with or without
// the "TLS_" prefix of cipher suites) or by hex value ("0xc02b").
func lookup(names map[uint16]string, s string) (uint16, bool) {
	s = strings.TrimSpace(s)
	if v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 16); err == nil && strings.HasPrefix(strings.ToLower(s), "0x") {
		return uint16(v), true
	}
	if v, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(v), true
	}
	for v, n := range names {
		if strings.EqualFold(n, s) || strings.EqualFold(strings.TrimPrefix(n, "TLS_"), s) {
			return v, true
		}
	}
	return 0, false
}

// ParseCipherSuite parses a cipher suite name or number.
func ParseCipherSuite(s string) (CipherSuite, bool) {
	v, ok := lookup(suiteNames, s)
	return CipherSuite(v), ok
}

// ParseGroup parses a group name or number.
func ParseGroup(s string) (Group, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "p-256", "p256", "prime256v1":
		return 0x0017, true
	case "p-384", "p384":
		return 0x0018, true
	case "p-521", "p521":
		return 0x0019, true
	}
	v, ok := lookup(groupNames, s)
	return Group(v), ok
}

// ParseSignatureScheme parses a signature scheme name or number.
func ParseSignatureScheme(s string) (SignatureScheme, bool) {
	v, ok := lookup(schemeNames, s)
	return SignatureScheme(v), ok
}

// parseText parses the text form of a code point: "name(0x....)", a bare
// name, or "0x....".
func parseText(b []byte, names map[uint16]string) (uint16, error) {
	s := string(b)
	if i := strings.LastIndex(s, "(0x"); i >= 0 && strings.HasSuffix(s, ")") {
		s = s[i+1 : len(s)-1]
	} else if strings.HasPrefix(s, "GREASE(") && strings.HasSuffix(s, ")") {
		s = s[len("GREASE(") : len(s)-1]
	}
	if v, ok := lookup(names, s); ok {
		return v, nil
	}
	return 0, fmt.Errorf("wire: unknown value %q", string(b))
}

// UnmarshalText parses the text form of MarshalText.
func (s *CipherSuite) UnmarshalText(b []byte) error {
	v, err := parseText(b, suiteNames)
	*s = CipherSuite(v)
	return err
}

// UnmarshalText parses the text form of MarshalText.
func (g *Group) UnmarshalText(b []byte) error {
	v, err := parseText(b, groupNames)
	*g = Group(v)
	return err
}

// UnmarshalText parses the text form of MarshalText.
func (s *SignatureScheme) UnmarshalText(b []byte) error {
	v, err := parseText(b, schemeNames)
	*s = SignatureScheme(v)
	return err
}

// UnmarshalText parses the text form of MarshalText.
func (e *ExtensionType) UnmarshalText(b []byte) error {
	v, err := parseText(b, extensionNames)
	*e = ExtensionType(v)
	return err
}

// UnmarshalText parses the text form of MarshalText.
func (v *Version) UnmarshalText(b []byte) error {
	for _, x := range []Version{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13} {
		if x.String() == string(b) {
			*v = x
			return nil
		}
	}
	x, err := parseText(b, nil)
	*v = Version(x)
	return err
}

func parseText8[T ~uint8](b []byte, str func(T) string) (T, error) {
	for i := 0; i < 256; i++ {
		if str(T(i)) == string(b) {
			return T(i), nil
		}
	}
	return 0, fmt.Errorf("wire: unknown value %q", string(b))
}

// UnmarshalText parses the text form of MarshalText.
func (t *HandshakeType) UnmarshalText(b []byte) (err error) {
	*t, err = parseText8(b, HandshakeType.String)
	return err
}

// UnmarshalText parses the text form of MarshalText.
func (t *RecordType) UnmarshalText(b []byte) (err error) {
	*t, err = parseText8(b, RecordType.String)
	return err
}

// UnmarshalText parses the text form of MarshalText.
func (a *AlertDescription) UnmarshalText(b []byte) (err error) {
	*a, err = parseText8(b, AlertDescription.String)
	return err
}
