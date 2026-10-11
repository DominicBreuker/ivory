// Package wire decodes the plaintext parts of TLS connections (records,
// handshake messages, alerts) and builds ClientHello messages. It knows
// nothing about keys: what is encrypted stays opaque.
package wire

import (
	"encoding/binary"
)

// maxRecord bounds the length of a record (RFC 8446, Section 5.2: 2^14
// plus 2048 bytes of expansion for TLS 1.2 and older).
const maxRecord = 1<<14 + 2048

// A Record is one TLS record.
type Record struct {
	Type    RecordType `json:"type"`
	Version Version    `json:"version"`
	Length  int        `json:"length"`
	payload []byte
}

// A Message is a handshake message.
type Message struct {
	Type HandshakeType
	Body []byte
}

// An Alert is a TLS alert.
type Alert struct {
	Level       uint8            `json:"level"`
	Description AlertDescription `json:"description"`
}

func (a Alert) String() string {
	level := "warning"
	if a.Level == 2 {
		level = "fatal"
	}
	return level + " " + a.Description.String()
}

// An Event is what one record of a stream carried.
type Event struct {
	Record Record
	// Messages are the handshake messages that this record completed.
	Messages []Message
	// Alert is set for a plaintext alert record.
	Alert *Alert
	// Encrypted marks a record whose content is protected: application
	// data records, and any record after a ChangeCipherSpec in the same
	// direction.
	Encrypted bool
	// ChangeCipherSpec marks a ChangeCipherSpec record.
	ChangeCipherSpec bool
}

// A Stream decodes the records of one direction of a connection as the
// bytes arrive. The zero value is ready to use.
type Stream struct {
	buf       []byte
	hs        []byte
	encrypted bool
	broken    bool
}

// Broken reports whether the stream held bytes that are not TLS records;
// Feed ignores everything after them.
func (s *Stream) Broken() bool { return s.broken }

// Feed adds bytes read from the connection and returns the events of the
// records they completed.
func (s *Stream) Feed(b []byte) []Event {
	if s.broken {
		return nil
	}
	s.buf = append(s.buf, b...)
	var events []Event
	for len(s.buf) >= 5 {
		typ := RecordType(s.buf[0])
		n := int(binary.BigEndian.Uint16(s.buf[3:5]))
		if typ < 20 || typ > 24 || s.buf[1] != 3 || n > maxRecord {
			s.broken = true
			s.buf = nil
			return events
		}
		if len(s.buf) < 5+n {
			break
		}
		rec := Record{Type: typ, Version: Version(binary.BigEndian.Uint16(s.buf[1:3])), Length: n, payload: s.buf[5 : 5+n]}
		s.buf = s.buf[5+n:]
		events = append(events, s.record(rec))
	}
	return events
}

func (s *Stream) record(rec Record) Event {
	ev := Event{Record: rec}
	switch {
	case rec.Type == RecordChangeCipherSpec:
		ev.ChangeCipherSpec = true
		s.encrypted = true
		s.hs = nil
	case s.encrypted || rec.Type == RecordApplicationData:
		ev.Encrypted = true
	case rec.Type == RecordAlert:
		if len(rec.payload) == 2 {
			ev.Alert = &Alert{Level: rec.payload[0], Description: AlertDescription(rec.payload[1])}
		}
	case rec.Type == RecordHandshake:
		s.hs = append(s.hs, rec.payload...)
		for len(s.hs) >= 4 {
			n := int(s.hs[1])<<16 | int(s.hs[2])<<8 | int(s.hs[3])
			if len(s.hs) < 4+n {
				break
			}
			ev.Messages = append(ev.Messages, Message{Type: HandshakeType(s.hs[0]), Body: append([]byte(nil), s.hs[4:4+n]...)})
			s.hs = s.hs[4+n:]
		}
	}
	return ev
}

// SplitRecords splits a byte string of complete records, as written by
// one side, into its events. It is Feed on a new Stream.
func SplitRecords(b []byte) []Event {
	var s Stream
	return s.Feed(b)
}

// Payload returns the record's content as it was on the wire.
func (r Record) Payload() []byte { return r.payload }
