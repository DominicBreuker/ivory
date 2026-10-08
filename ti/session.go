package ti

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// MaxSessionAge is how long a TLS session may be resumed after its full
// handshake: gemSpec_Krypt GS-A_5322 asks for the key material from the
// Diffie-Hellman exchange to be deleted after at most 24 hours.
const MaxSessionAge = 24 * time.Hour

// SessionTickets manages the session ticket keys of a TLS 1.2 server for
// GS-A_5322: ticket keys change at the latest every 48 hours, and sessions
// older than MaxSessionAge are not resumed. The zero value is ready to use.
//
// Go cannot guarantee that old keys are erased from memory (the garbage
// collector may keep copies); SessionTickets drops every reference to them.
type SessionTickets struct {
	// Time returns the current time. If nil, time.Now is used.
	Time func() time.Time

	mu   sync.Mutex
	keys [][32]byte // newest first, at most two
}

func (s *SessionTickets) now() time.Time {
	if s.Time != nil {
		return s.Time()
	}
	return time.Now()
}

// Enable turns on session tickets in config with a fresh key, and sets
// config.UnwrapSession to reject sessions older than MaxSessionAge. Call
// Rotate at least every 24 hours afterwards. config must be the
// tls.Config that the server uses, not a copy: UnwrapSession decrypts
// tickets with its keys.
func (s *SessionTickets) Enable(config *tls.Config) error {
	config.SessionTicketsDisabled = false
	config.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		state, err := config.DecryptTicket(identity, cs)
		if err != nil || state == nil {
			return nil, err
		}
		created, err := sessionCreated(state)
		if err != nil || s.now().Sub(created) > MaxSessionAge {
			return nil, nil // full handshake
		}
		return state, nil
	}
	return s.Rotate(config)
}

// Rotate sets a new session ticket key on config and keeps only the
// previous one for decryption. Called every 24 hours, it keeps every key
// younger than 48 hours (GS-A_5322).
func (s *SessionTickets) Rotate(config *tls.Config) error {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append([][32]byte{k}, s.keys...)
	if len(s.keys) > 2 {
		s.keys[2] = [32]byte{}
		s.keys = s.keys[:2]
	}
	config.SetSessionTicketKeys(s.keys)
	return nil
}

// sessionCreated returns the creation time encoded in state: on a server,
// the time of the full handshake that produced the session's secret (Go
// keeps it when it re-issues a ticket on resumption).
func sessionCreated(state *tls.SessionState) (time.Time, error) {
	b, err := state.Bytes()
	if err != nil {
		return time.Time{}, err
	}
	// uint16 version, uint8 type, uint16 cipher_suite, uint64 created_at
	// (crypto/tls, SessionState encoding).
	if len(b) < 13 {
		return time.Time{}, errors.New("ti: short session state")
	}
	return time.Unix(int64(binary.BigEndian.Uint64(b[5:13])), 0), nil
}

// sessionSecret returns a hash of the secret of state, which identifies the
// key material of a session across resumptions.
func sessionSecret(state *tls.SessionState) ([32]byte, error) {
	b, err := state.Bytes()
	if err != nil {
		return [32]byte{}, err
	}
	// After the 13 bytes above: opaque secret<1..2^8-1>.
	if len(b) < 14 || len(b) < 14+int(b[13]) {
		return [32]byte{}, errors.New("ti: short session state")
	}
	return sha256.Sum256(b[14 : 14+int(b[13])]), nil
}

// NewClientSessionCache returns a tls.ClientSessionCache for TLS 1.2
// clients that holds up to capacity sessions and forgets a session
// MaxSessionAge after the full handshake that produced its secret, even if
// the server has issued new tickets for it since (GS-A_5322). now returns
// the current time; if nil, time.Now is used.
func NewClientSessionCache(capacity int, now func() time.Time) tls.ClientSessionCache {
	if now == nil {
		now = time.Now
	}
	return &clientSessionCache{
		lru:   tls.NewLRUClientSessionCache(capacity),
		now:   now,
		first: make(map[[32]byte]time.Time),
	}
}

type clientSessionCache struct {
	lru tls.ClientSessionCache
	now func() time.Time

	mu    sync.Mutex
	first map[[32]byte]time.Time // when a secret was first seen
}

func (c *clientSessionCache) Put(key string, cs *tls.ClientSessionState) {
	if cs == nil {
		c.lru.Put(key, nil)
		return
	}
	_, state, err := cs.ResumptionState()
	if err != nil || state == nil {
		return
	}
	id, err := sessionSecret(state)
	if err != nil {
		return
	}
	now := c.now()
	c.mu.Lock()
	for k, t := range c.first {
		if now.Sub(t) > MaxSessionAge {
			delete(c.first, k)
		}
	}
	first, ok := c.first[id]
	if !ok {
		first = now
		c.first[id] = now
	}
	c.mu.Unlock()
	if now.Sub(first) > MaxSessionAge {
		c.lru.Put(key, nil)
		return
	}
	c.lru.Put(key, cs)
}

func (c *clientSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	cs, ok := c.lru.Get(key)
	if !ok {
		return nil, false
	}
	_, state, err := cs.ResumptionState()
	if err == nil && state != nil {
		if id, err := sessionSecret(state); err == nil {
			c.mu.Lock()
			first, known := c.first[id]
			c.mu.Unlock()
			if known && c.now().Sub(first) <= MaxSessionAge {
				return cs, true
			}
		}
	}
	c.lru.Put(key, nil)
	return nil, false
}
