# Contributing

Thank you for helping. The most valuable contribution right now is
**field experience**: does ivory work with your TI peers?

- **Interop reports:** open an issue with the "Interop report" template.
  Say which product, version and role (Konnektor, card terminal,
  Fachdienst, test tool) you connected to, the TLS version, curve and
  overlay profile, and what happened. Successes help as much as failures.
- **Bugs:** open an issue with the "Bug report" template, with the ivory
  version, the Go release (`go version`), the profile, and the output of
  `scripts/ivory-overlay doctor -profile <profile>`.
- **Security problems:** see [SECURITY.md](SECURITY.md). Don't open a
  public issue.

## Pull requests

Pull requests are welcome, but please open an issue first for anything
bigger than a small fix. Changes are prepared and tested outside this
repository and then published here together with the release, so a pull
request is applied by the maintainer and closed rather than merged; you
are credited in the commit.

Rules a change has to follow:

- **The overlay patches stay generic.** No Brainpool math, OIDs or
  Brainpool-specific API in a patch: patches open extension points that
  any unsupported algorithm can use. Each patch is one concern, in Go's
  style, with tests in the style of the Go tree that need no Brainpool
  math ([overlay/README.md](overlay/README.md), "Adding or changing a
  patch").
- **No global registries.** Everything goes through `tls.Config`,
  `x509.VerifyOptions` or explicit calls.
- **Hooks are opt-in, fail closed, and are off in FIPS 140-3 mode.**
- **Constant time** for everything that touches secrets: no `math/big`
  and no `bigmod` VarTime functions on secrets. Changes to `brainpool`
  update [docs/brainpool-constant-time.md](docs/brainpool-constant-time.md).
- **Tests first,** and these checks before you send a change:

  ```sh
  gofmt -l $(git ls-files '*.go')
  go vet ./... && go test ./...                      # stock pinned Go
  eval "$(scripts/ivory-overlay env -profile core)"  # then with the overlay
  go vet ./... && go test ./...
  scripts/ivory-overlay stdtest -profile core
  go -C cmd/ivory-overlay vet ./... && go -C cmd/ivory-overlay test ./...
  shellcheck -S warning scripts/ivory-overlay scripts/*.sh
  ```

By contributing, you agree that your contribution is licensed under the
BSD-3-Clause license of this repository ([LICENSE](LICENSE)).
