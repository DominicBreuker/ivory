---
name: Interop report
about: Tell us how ivory works (or doesn't) with a TLS peer, for example a TI product
title: 'Interop: <peer> (<role>)'
labels: interop
---

**Peer:** product, vendor, version (for example a Konnektor, card
terminal, Fachdienst, gematik test tool, or a TLS library)

**Role of the Go program:** client or server; card terminal, Konnektor-like
client, Fachdienst, other

**Result:** works / fails

**Setup**

- ivory version:
- `go version`:
- overlay profile (`core` or `kt`):
- TLS version (1.2 or 1.3):
- certificates: curves of the end-entity and CA certificates; key in
  software or on a card
- configuration: `ti` preset (which?) or your own `tls.Config`

**What happened**

Error messages, alerts, logs. A packet capture or `openssl s_client` /
`s_server` output helps a lot. Remove private keys and personal data
first.
