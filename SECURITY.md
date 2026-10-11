# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub's private
vulnerability reporting: open the repository's **Security** tab and
choose **Report a vulnerability**. Don't open a public issue.

Include what you found, how to reproduce it, the ivory version, the Go
release and the overlay profile. You will get an answer within a week.
Fixes are released as a new ivory version and announced in a GitHub
security advisory.

## Supported versions

Only the latest ivory version gets security fixes. Each version supports
one Go release; when Go publishes a security release, ivory adopts it in
a new version.

## Scope

In scope: the Brainpool code (`brainpool`, `x509util`), the TLS glue
(`tlsutil`, `ti`), the TSL and OCSP checks (`tsl`, `ocsp`, and the XML
canonicalization and signature code in `internal/xmldsig`), the overlay
patches, the overlay tool (`cmd/ivory-overlay`, `scripts/ivory-overlay`),
and the `ivory` test tool (`cmd/ivory`). The examples (`examples/`) are
in scope where they show a configuration that users would copy.

Security fixes in Go itself reach ivory when ivory adopts the Go release
that contains them. Report problems in unpatched parts of Go to the Go
project (https://go.dev/security/policy).

[docs/security.md](docs/security.md) describes what ivory does and doesn't
guarantee: constant time, random numbers, erasure of secrets, the
choices in the TLS configurations, the TSL and OCSP checks, and what the
`ivory` test tool trusts.
