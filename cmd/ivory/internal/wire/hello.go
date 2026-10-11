package wire

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// A HelloSpec describes a ClientHello to build. Lists that are nil leave
// their extension out.
type HelloSpec struct {
	// Version is the legacy_version; RecordVersion the version of the
	// record (TLS 1.0 if zero).
	Version, RecordVersion Version
	CipherSuites           []CipherSuite
	// Compression are the compression methods; nil means null only.
	Compression []uint8

	ServerName          string
	SupportedVersions   []Version
	SupportedGroups     []Group
	SignatureAlgorithms []SignatureScheme
	// EmptyKeyShare sends the key_share extension with no shares, which
	// makes a TLS 1.3 server answer with a HelloRetryRequest that names
	// its choice of group and cipher suite.
	EmptyKeyShare bool
	ALPN          []string

	ECPointFormats       bool // uncompressed only
	ExtendedMasterSecret bool
	RenegotiationInfo    bool // empty renegotiated_connection
	SessionTicket        bool // empty ticket
	StatusRequest        bool // OCSP, no responder IDs or extensions
	EncryptThenMAC       bool
	SCT                  bool
	Heartbeat            bool // peer_allowed_to_send
	PSKModes             bool // psk_dhe_ke
	// RecordSizeLimit, if not zero, is sent as record_size_limit.
	RecordSizeLimit uint16
	// MaxFragmentLength, if not zero, is the max_fragment_length code
	// (1 to 4).
	MaxFragmentLength uint8

	// Extra extensions are appended as they are.
	Extra []Extension
}

// Marshal returns the ClientHello as a handshake message.
func (h *HelloSpec) Marshal() []byte {
	var b cryptobyte.Builder
	b.AddUint8(uint8(TypeClientHello))
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(uint16(h.Version))
		random := make([]byte, 32)
		rand.Read(random)
		b.AddBytes(random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			if h.SupportedVersions != nil {
				// A compatibility-mode session ID, as clients send it
				// (RFC 8446, Appendix D.4).
				sid := make([]byte, 32)
				rand.Read(sid)
				b.AddBytes(sid)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, s := range h.CipherSuites {
				b.AddUint16(uint16(s))
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			if h.Compression == nil {
				b.AddUint8(0)
			}
			b.AddBytes(h.Compression)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { h.extensions(b) })
	})
	return b.BytesOrPanic()
}

func (h *HelloSpec) extensions(b *cryptobyte.Builder) {
	ext := func(t ExtensionType, body func(b *cryptobyte.Builder)) {
		b.AddUint16(uint16(t))
		b.AddUint16LengthPrefixed(body)
	}
	if h.ServerName != "" {
		ext(ExtServerName, func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(0)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(h.ServerName)) })
			})
		})
	}
	if h.ExtendedMasterSecret {
		ext(ExtExtendedMasterSecret, func(*cryptobyte.Builder) {})
	}
	if h.RenegotiationInfo {
		ext(ExtRenegotiationInfo, func(b *cryptobyte.Builder) { b.AddUint8(0) })
	}
	if h.SupportedGroups != nil {
		ext(ExtSupportedGroups, func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, g := range h.SupportedGroups {
					b.AddUint16(uint16(g))
				}
			})
		})
	}
	if h.ECPointFormats {
		ext(ExtECPointFormats, func(b *cryptobyte.Builder) {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
		})
	}
	if h.SessionTicket {
		ext(ExtSessionTicket, func(*cryptobyte.Builder) {})
	}
	if h.ALPN != nil {
		ext(ExtALPN, func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, p := range h.ALPN {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(p)) })
				}
			})
		})
	}
	if h.StatusRequest {
		ext(ExtStatusRequest, func(b *cryptobyte.Builder) {
			b.AddUint8(1)  // ocsp
			b.AddUint16(0) // responder_id_list
			b.AddUint16(0) // request_extensions
		})
	}
	if h.SignatureAlgorithms != nil {
		ext(ExtSignatureAlgorithms, func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, s := range h.SignatureAlgorithms {
					b.AddUint16(uint16(s))
				}
			})
		})
	}
	if h.SCT {
		ext(ExtSCT, func(*cryptobyte.Builder) {})
	}
	if h.EncryptThenMAC {
		ext(ExtEncryptThenMAC, func(*cryptobyte.Builder) {})
	}
	if h.Heartbeat {
		ext(ExtHeartbeat, func(b *cryptobyte.Builder) { b.AddUint8(1) })
	}
	if h.RecordSizeLimit != 0 {
		ext(ExtRecordSizeLimit, func(b *cryptobyte.Builder) { b.AddUint16(h.RecordSizeLimit) })
	}
	if h.MaxFragmentLength != 0 {
		ext(ExtMaxFragmentLength, func(b *cryptobyte.Builder) { b.AddUint8(h.MaxFragmentLength) })
	}
	if h.SupportedVersions != nil {
		ext(ExtSupportedVersions, func(b *cryptobyte.Builder) {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, v := range h.SupportedVersions {
					b.AddUint16(uint16(v))
				}
			})
		})
	}
	if h.PSKModes {
		ext(ExtPSKModes, func(b *cryptobyte.Builder) {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(1) })
		})
	}
	if h.EmptyKeyShare {
		ext(ExtKeyShare, func(b *cryptobyte.Builder) { b.AddUint16(0) })
	}
	for _, e := range h.Extra {
		ext(e.Type, func(b *cryptobyte.Builder) { b.AddBytes(e.Data) })
	}
}

// Records wraps a handshake message in handshake records of the given
// record version (TLS 1.0 if zero).
func Records(version Version, msg []byte) []byte {
	if version == 0 {
		version = VersionTLS10
	}
	var out []byte
	for len(msg) > 0 {
		n := min(len(msg), 1<<14)
		out = append(out, byte(RecordHandshake), byte(version>>8), byte(version), byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

// Bytes returns the ClientHello in records, ready to send.
func (h *HelloSpec) Bytes() []byte { return Records(h.RecordVersion, h.Marshal()) }

// JA3 returns the JA3 string of a ClientHello and its MD5 hash: version,
// cipher suites, extensions, groups and point formats, GREASE values left
// out.
func JA3(ch *ClientHello) (string, string) {
	var suites, exts, grps, pfs []string
	for _, s := range ch.CipherSuites {
		if !IsGREASE(uint16(s)) {
			suites = append(suites, fmt.Sprint(uint16(s)))
		}
	}
	for _, e := range ch.Extensions {
		if !IsGREASE(uint16(e.Type)) {
			exts = append(exts, fmt.Sprint(uint16(e.Type)))
		}
	}
	for _, g := range ch.SupportedGroups {
		if !IsGREASE(uint16(g)) {
			grps = append(grps, fmt.Sprint(uint16(g)))
		}
	}
	for _, p := range ch.ECPointFormats {
		pfs = append(pfs, fmt.Sprint(p))
	}
	s := fmt.Sprintf("%d,%s,%s,%s,%s", uint16(ch.Version),
		strings.Join(suites, "-"), strings.Join(exts, "-"), strings.Join(grps, "-"), strings.Join(pfs, "-"))
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}
