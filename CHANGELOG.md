# Changelog

Notable changes per release. Entries say what changed in the shipped binary and
why; the commit messages carry the detail and the measurements behind them.

This project follows [semantic versioning](https://semver.org/). While the major
version is 0, a minor bump may change flag semantics — each one below says so.

## [0.3.1] — 2026-08-18

Nothing in the proxy itself changed. The binary is rebuilt on Go 1.26.6, which
carries three standard-library fixes; none of them appears to be triggerable in
this program, so this is hygiene rather than an urgent upgrade.

### Security

- **Rebuilt on Go 1.26.6.** It fixes three advisories that `govulncheck`
  reaches from this binary: [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090)
  in `crypto/tls`, where post-handshake `KeyUpdate` messages were always treated
  as state-advancing and could be replayed to force repeated key derivation;
  [GO-2026-6089](https://pkg.go.dev/vuln/GO-2026-6089) in `net/http`, where
  `ReadHeaderTimeout` was not applied while sniffing a new connection for the
  unencrypted HTTP/2 preface; and
  [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972) in `encoding/asn1`,
  where `Unmarshal` had no recursion limit.

  Reachable is not the same as exploitable, and as far as the conditions each
  one needs go, this binary meets none of them: it opens no TLS connection of
  its own — the legacy backends it exists to talk to predate any TLS worth
  configuring — the health server leaves `Protocols` at the default, so it never
  offers unencrypted HTTP/2, and nothing here parses ASN.1. The traces run
  through `serveHealth`, the packet reader and `signal.NotifyContext`, which is
  the call graph being conservative rather than three live holes. The bump is
  still the right move: the standard library is the whole dependency tree here,
  so keeping it current is the only supply-chain lever this project has.

### Build

- The Go toolchain is pinned in `go.mod` as well as in the `Dockerfile`, and
  both now move together. The image bump alone left the scan red, because
  `govulncheck` runs against the toolchain named in `go.mod` — the released
  image would have been clean while CI said otherwise.
- Release notes are taken from this file: the tag workflow publishes the section
  for the version being tagged, falling back to commit subjects for the releases
  that predate it.

## [0.3.0] — 2026-08-12

Two of these are availability fixes reachable from the network, so this release
supersedes 0.2.0 and 0.1.0 rather than merely improving on them.

### Security

- **A malformed handshake could panic the process, before authentication.** A
  username with no NUL terminator left the parser's cursor past the end of the
  packet, and the length-encoded auth-response branch then sliced at it. A
  client sets that capability itself, so any host able to open a socket could
  crash the proxy — taking down every other connection it was relaying, not
  just its own. Every offset is now checked before use, and the tests truncate
  a valid packet at every length with every capability bit set.
- **A query could panic the process after authentication.** Both query rewrites
  indexed the original statement using offsets taken from a Unicode-lowercased
  copy of it. Unicode folding changes byte lengths — U+212A KELVIN SIGN is three
  bytes and folds to a one-byte `k` — so a statement mixing such a character
  with a rewrite trigger read out of bounds. Folding is now ASCII-only, which
  cannot change length.

### Fixed

- **Schema-qualified queries failed.** `CLIENT_NO_SCHEMA` was carried end to
  end on the grounds that it changes no framing, which is true and beside the
  point: it makes the server reject `database.table` qualifiers, so every such
  query resolved against the default schema and failed. Framing is not the only
  way a capability can be unsafe to relay.
- **Sessions could differ across the two halves.** The relay negotiated its
  whole safe capability set with the backend regardless of what the client had
  asked for. A capability enabled on one side only changes what statements
  mean: `CLIENT_FOUND_ROWS` alone would have an `UPDATE` report matched rows to
  one side and changed rows to the other. The backend session now mirrors the
  client's, with connection-phase flags still following the server.
- **The `utf8mb4` rewrite invented collations.** Renaming `utf8mb4_0900_ai_ci`
  to `utf8_0900_ai_ci` produces a collation no server has ever had, so MySQL
  8.0's default collation turned one failure into another. Suffixes the old
  `utf8` character set really has are carried across; anything else becomes
  `utf8_general_ci`. The list of what it really has was measured on MySQL 5.5.
- **The `DATETIME_PRECISION` shim fired everywhere.** Against a server that has
  the column — MySQL 5.6 supports both it and `mysql_old_password`, so it is a
  legitimate backend here — substituting `0` reported `DATETIME(3)` as 19 wide
  instead of 23. It is now gated on the backend's version, read from the
  handshake: MySQL before 5.6, MariaDB before 5.3. MariaDB is recognised behind
  the `5.5.5-` prefix it puts in front of its real version, which read literally
  would have triggered the shim on a server that has the column.
- `make cover` wrote into `bin/` without creating it.

### Changed

- `-rewrite-datetime-precision` takes `auto` (the default), `always` or
  `never`, rather than a boolean. `true` and `false` still work and still mean
  what they did; `auto` is new, and is why this is a minor bump.

## [0.2.0] — 2026-08-12

### Added

- **`-rewrite-datetime-precision`**, substituting `0` for the
  `DATETIME_PRECISION` column in `information_schema` queries. The column
  arrived in MySQL 5.6 and drivers select it unconditionally when reading
  column metadata, so on a 5.0 or 5.1 server every schema read failed with
  `Unknown column 'DATETIME_PRECISION' in 'field list'` — leaving a proxy that
  authenticated to a server no JDBC client could browse. `0` rather than `NULL`,
  because the driver computes column sizes arithmetically from the value.

  Measured against a real MySQL 5.0.77 through the proxy.

### Build

- The image cross-compiles instead of emulating the build stage. `buildx` was
  running the Go compiler itself under QEMU for the foreign architecture, which
  is why a multi-architecture build took 6m47s; it now takes 64s.
- Dependabot watches the workflows and the Dockerfile's pinned Go builder, and
  the actions in use were brought up to date — several were majors behind.

## [0.1.0] — 2026-08-11

First release.

- Terminates authentication separately on each side: `mysql_native_password`
  towards clients, pre-4.1 `mysql_old_password` towards the legacy server, then
  relays the packet stream. Standard library only.
- Offers clients only capabilities the backend also supports, from a set that
  excludes everything known to change post-authentication framing, so a byte
  copy cannot silently corrupt result sets. Re-checked against the live backend
  handshake before anything is relayed.
- `-rewrite-utf8mb4` for servers predating `utf8mb4`, and `-fake-ok-regex` for
  driver session setup a legacy server rejects outright.
- Separate credentials on each side, from the environment rather than flags, or
  one credential with `-frontend-password-from-backend`.
- `-max-connections`, a health endpoint on its own port so probes never reach
  the legacy server, and graceful draining on `SIGTERM`.
- Published as a single static binary on `scratch`: no shell, no libc, nothing
  else in the image.

[0.3.1]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ralforion/mysql-old-password-proxy/releases/tag/v0.1.0
