# Third-party notices

`mysql-old-password-proxy` has **no third-party dependencies**. It is written
against the Go standard library alone: `go.mod` declares no `require`
directives, and the repository has no `go.sum` because there is nothing to
verify.

The released binary therefore redistributes no third-party code, and there is
no attribution anyone is owed for it. The proxy itself is covered by
[LICENSE](LICENSE).

Two things this does not cover. The Go runtime and standard library are
compiled into the binary and are BSD-3-Clause; their text ships with the
toolchain and at <https://go.dev/LICENSE>. The container image additionally
carries whatever its base image does, with those terms under
`/usr/share/doc/*/copyright` inside it.

This file is generated. Run `./scripts/gen-notices.sh` after changing a
dependency; CI fails when it is out of date. Add a dependency and this same
script will start listing it here, with its licence text in full.
