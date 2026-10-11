//go:build ivory

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/DominicBreuker/ivory/cmd/ivory/internal/wire"
)

// Directions of the records in a trace.
const (
	dirC2S = "C->S"
	dirS2C = "S->C"
)

// maxTraceEvents bounds the events a trace keeps (application data on a
// long connection).
const maxTraceEvents = 2000

// A traceEvent is one record of a connection, or a note from a crypto/tls
// callback.
type traceEvent struct {
	Time      float64        `json:"t"`
	Dir       string         `json:"dir,omitempty"`
	Record    *wire.Record   `json:"record,omitempty"`
	Encrypted bool           `json:"encrypted,omitempty"`
	Messages  []traceMessage `json:"messages,omitempty"`
	Alert     *wire.Alert    `json:"alert,omitempty"`
	Payload   wire.HexBytes  `json:"payload,omitempty"`
	Note      string         `json:"note,omitempty"`
	ccs       bool
	raw       []wire.Message
}

type traceMessage struct {
	Type   wire.HandshakeType `json:"type"`
	Length int                `json:"length"`
	Detail []string           `json:"detail,omitempty"`
}

// A handshakeLog decodes both directions of a connection as they pass,
// keeps what the reports need (the plaintext handshake messages), and,
// when tracing, prints every record.
type handshakeLog struct {
	mu       sync.Mutex
	start    time.Time
	c2s, s2c wire.Stream
	events   []traceEvent
	dropped  int
	live     io.Writer // text trace output, or nil
	hex      bool
	keep     bool // keep events for the JSON report

	version     wire.Version
	clientHello *wire.ClientHello
	serverHello *wire.ServerHello
	ske         *wire.ServerKeyExchange
	certReq     *wire.CertificateRequest
	serverCerts [][]byte
	clientCerts [][]byte
	stapled     bool
	alerts      map[string]*wire.Alert // first plaintext alert per direction
	ccs         map[string]bool
}

func newHandshakeLog(live io.Writer, hexDump, keep bool) *handshakeLog {
	return &handshakeLog{start: time.Now(), live: live, hex: hexDump, keep: keep,
		alerts: map[string]*wire.Alert{}, ccs: map[string]bool{}}
}

func (h *handshakeLog) since() float64 { return time.Since(h.start).Seconds() }

// note records a remark from a crypto/tls callback.
func (h *handshakeLog) note(format string, args ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ev := traceEvent{Time: h.since(), Note: fmt.Sprintf(format, args...)}
	h.add(ev)
	if h.live != nil {
		fmt.Fprintf(h.live, "%8.3f      %s\n", ev.Time, ev.Note)
	}
}

func (h *handshakeLog) add(ev traceEvent) {
	if !h.keep {
		return
	}
	if len(h.events) >= maxTraceEvents {
		h.dropped++
		return
	}
	h.events = append(h.events, ev)
}

// feed decodes bytes that went in direction dir.
func (h *handshakeLog) feed(dir string, b []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &h.c2s
	if dir == dirS2C {
		s = &h.s2c
	}
	for _, e := range s.Feed(b) {
		rec := e.Record
		ev := traceEvent{Time: h.since(), Dir: dir, Record: &rec, Encrypted: e.Encrypted, Alert: e.Alert, ccs: e.ChangeCipherSpec, raw: e.Messages}
		if h.hex {
			ev.Payload = wire.HexBytes(rec.Payload())
		}
		if e.Alert != nil && h.alerts[dir] == nil {
			h.alerts[dir] = e.Alert
		}
		if e.ChangeCipherSpec {
			h.ccs[dir] = true
		}
		for _, m := range e.Messages {
			h.capture(dir, m)
			ev.Messages = append(ev.Messages, traceMessage{Type: m.Type, Length: len(m.Body), Detail: wire.Describe(m, h.version)})
		}
		h.add(ev)
		if h.live != nil {
			h.print(ev)
		}
	}
	if s.Broken() && h.live != nil {
		fmt.Fprintf(h.live, "%8.3f %s (bytes that are not TLS records; decoding stops)\n", h.since(), dir)
	}
}

func (h *handshakeLog) capture(dir string, m wire.Message) {
	switch m.Type {
	case wire.TypeClientHello:
		if ch, err := wire.ParseClientHello(m.Body); err == nil && h.clientHello == nil {
			h.clientHello = ch
		}
	case wire.TypeServerHello:
		if sh, err := wire.ParseServerHello(m.Body); err == nil {
			h.serverHello = sh
			if !sh.HelloRetryRequest {
				h.version = sh.Negotiated()
			}
		}
	case wire.TypeCertificate:
		if h.version == wire.VersionTLS13 {
			return // encrypted, never seen here
		}
		certs, err := wire.ParseCertificate(m.Body, false)
		if err != nil {
			return
		}
		if dir == dirS2C {
			h.serverCerts = certs
		} else {
			h.clientCerts = certs
		}
	case wire.TypeServerKeyExchange:
		if ske, err := wire.ParseServerKeyExchange(m.Body, h.version); err == nil {
			h.ske = ske
		}
	case wire.TypeCertificateRequest:
		if h.version != wire.VersionTLS13 {
			if cr, err := wire.ParseCertificateRequest(m.Body, h.version); err == nil {
				h.certReq = cr
			}
		}
	case wire.TypeCertificateStatus:
		h.stapled = true
	}
}

func (h *handshakeLog) print(ev traceEvent) {
	w := h.live
	r := ev.Record
	line := fmt.Sprintf("%8.3f %s %s %v, %d bytes", ev.Time, ev.Dir, r.Type, r.Version, r.Length)
	switch {
	case ev.ccs:
		line += " (encrypted from here on)"
	case ev.Alert != nil:
		line += ": " + ev.Alert.String()
	case ev.Encrypted:
		line += " (encrypted)"
	}
	fmt.Fprintln(w, line)
	for _, m := range ev.Messages {
		fmt.Fprintf(w, "               %v (%d bytes)\n", m.Type, m.Length)
		for _, d := range m.Detail {
			fmt.Fprintf(w, "                 %s\n", d)
		}
	}
	if h.hex {
		for _, l := range strings.Split(strings.TrimRight(hex.Dump(r.Payload()), "\n"), "\n") {
			fmt.Fprintf(w, "               %s\n", l)
		}
	}
}

// trace returns the kept events.
func (h *handshakeLog) trace() []traceEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dropped > 0 {
		return append(h.events, traceEvent{Note: fmt.Sprintf("%d more records not kept", h.dropped)})
	}
	return h.events
}

// tracedConn feeds everything it reads and writes to a handshakeLog.
type tracedConn struct {
	net.Conn
	log *handshakeLog
	// client is true on the client side: writes go C->S.
	client bool
}

func (c *tracedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		dir := dirS2C
		if !c.client {
			dir = dirC2S
		}
		c.log.feed(dir, b[:n])
	}
	return n, err
}

func (c *tracedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		dir := dirC2S
		if !c.client {
			dir = dirS2C
		}
		c.log.feed(dir, b[:n])
	}
	return n, err
}
