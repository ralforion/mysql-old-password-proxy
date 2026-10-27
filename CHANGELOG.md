# Changelog

Notable changes per release. Entries say what changed in the shipped binary and
why; the commit messages carry the detail and the measurements behind them.

This project follows [semantic versioning](https://semver.org/). While the major
version is 0, a minor bump may change flag semantics — each one below says so.

## [0.3.5] — 2026-10-27

Nothing in the proxy itself changed. The binary is rebuilt on Go 1.26.10 for
one advisory that `govulncheck` reaches through the call graph but that the
running program never triggers. It is back to hygiene, unlike 0.3.4.

### Security

- **Rebuilt on Go 1.26.10.** On 1.26.9 `govulncheck` reports
  [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809): `crypto/x509` gains a
  denylist so that `Certificate.Verify` rejects a set of compromised
  intermediate certificates, for systems whose trust stores have not caught up.
  `crypto/x509` is linked in, through `net/http` for the health server, but
  `Verify` only runs while verifying a peer's chain in a TLS handshake, and this
  binary never does one: the health server has no TLS, and the relay is
  plaintext on both sides and rejects an `SSLRequest`. The trace `govulncheck`
  prints starts at `io.ReadFull` in `mysqlwire.ReadPacketInto`, because it
  cannot rule out a `tls.Conn` behind the `io.Reader`.

  The image pin and the `go` directive moved together, as in 0.3.4.

### Build

- **`docker/login-action` moved to v4.7.0.** Its changes are in ECR and Docker
  Hub OIDC login and its dependencies. The release job logs in to Docker Hub
  with a username and token, which behaves as before. It is re-pinned to the
  commit its tag names.

## [0.3.4] — 2026-10-15

Nothing in the proxy itself changed. The binary is rebuilt on Go 1.26.9, a
security release, and unlike the last three rebuilds one of its fixes does
reach this program: the health endpoint could be talked into serving requests
after a `CONNECT`. It is low impact and needs an unusual deployment to matter,
but it is a real behaviour of the shipped binary, not a call graph being
conservative.

### Security

- **Rebuilt on Go 1.26.9.** On 1.26.8 `govulncheck` reaches seven advisories
  from this binary, in `net/http`, `crypto/tls` and `net/textproto`. One applies:

  - [GO-2026-6613](https://pkg.go.dev/vuln/GO-2026-6613) in `net/http`: when a
    handler answers an HTTP/1 `CONNECT` with a 2xx and returns without hijacking
    the connection, the server kept reading the rest of the connection as HTTP,
    although a 2xx to `CONNECT` turns it into a tunnel. The health handlers are
    registered without a method, so `CONNECT /healthz` gets a `200`. Sending
    that with a `GET /readyz` behind it on one connection gets two responses
    on 1.26.8 and one on 1.26.9, which closes the connection instead.

    What it enables is request smuggling, and only where something in front of
    the health port forwards `CONNECT` and then treats the connection as a
    tunnel. A kubelet probing the port directly does not. The endpoints are
    read-only and expose nothing beyond the version, the backend capability
    flags and a connection count, so the most a smuggled request can do is
    read those.

  The other six need something this binary never does:

  - [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603),
    [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611),
    [GO-2026-6612](https://pkg.go.dev/vuln/GO-2026-6612) and
    [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617) are all in the HTTP/2
    server: memory exhaustion through declared `Trailer` fields, CPU through
    repeated `SETTINGS_INITIAL_WINDOW_SIZE` changes, a double flow-control
    refund, and a crash from an HPACK encoder race. The health server speaks
    HTTP/1 only. It has no TLS, so no ALPN, and it leaves `Protocols` at the
    default, so it never offers unencrypted HTTP/2.
  - [GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607), memory exhaustion
    from repeated ECH outer extension references, is in the `crypto/tls`
    server. Nothing here terminates TLS.
  - [GO-2026-6608](https://pkg.go.dev/vuln/GO-2026-6608) bypasses the memory
    limit while parsing multipart MIME headers. The health handlers never read
    the request body, let alone parse a form.

  The image pin and the `go` directive moved together again. Dependabot bumped
  only the `Dockerfile`, so the scan stayed on 1.26.8 and went red on exactly
  these seven until `go.mod` followed.

### Build

- **`docker/build-push-action` moved to v7.4.0**, which stops printing buildx
  metadata to the job log unescaped. Since buildx v0.30.0 that metadata can
  carry the whole GitHub event payload, so a commit message could inject
  workflow commands into the release job, which holds the Docker Hub token.
  The commit messages it sees are ours and Dependabot's, so there was little
  exposure, but the fix is worth having. `docker/setup-qemu-action` (v4.4.0)
  and `docker/setup-buildx-action` (v4.4.1) moved alongside it, and the release
  notes of neither touch anything this build uses. All three are re-pinned to
  the commits their tags name.

## [0.3.3] — 2026-09-08

Nothing in the proxy itself changed, and this time nothing in the toolchain
reaches it either. The binary is rebuilt on Go 1.26.8, whose fixes are all in
code this build never compiles, never imports or never runs. Hygiene, on the
same reasoning as 0.3.1 and 0.3.2, with less behind it than either.

### Build

- **Rebuilt on Go 1.26.8.** It carries no advisories, so `govulncheck` reports
  the same nothing before and after. Its six backports miss this binary on four
  separate grounds:

  - [#80851](https://github.com/golang/go/issues/80851), a `#cgo` directive
    whose `FFLAGS` value was mixed up with `CXXFLAGS`, needs cgo — and this
    builds with `CGO_ENABLED=0`, which is what makes the `scratch` image
    possible in the first place.
  - [#80827](https://github.com/golang/go/issues/80827), where async preemption
    corrupted AVX (YMM) register state, is netbsd/amd64. The images are
    linux/amd64 and linux/arm64.
  - [#81113](https://github.com/golang/go/issues/81113), a PowerPC relocation
    broken in `debug/elf`, is in a package this tree does not import.
  - [#81152](https://github.com/golang/go/issues/81152) and
    [#80889](https://github.com/golang/go/issues/80889) are failures in Go's
    own test suite, and [#77800](https://github.com/golang/go/issues/77800) is
    `cmd/fix` reporting fixes it had not applied. None of the three reaches a
    shipped artifact.

  The image pin and the `go` directive moved together, as they have since
  0.3.1. That is not bookkeeping: `govulncheck` builds with the toolchain
  `go.mod` names while the released image is built with the one the
  `Dockerfile` pins, and it was letting those two drift that left the scan red
  when 0.3.1's image bump first landed on its own.

- **`docker/setup-qemu-action` moved to v4.3.0**, re-pinned to the commit that
  tag names and checked against upstream by `scripts/check-action-pins.sh`. The
  release is dependency bumps inside the action itself, so nothing changes about
  how binfmt handlers are registered before the arm64 cross-build.

- Go 1.27 is still deferred, and now has a patch release of its own in 1.27.1.
  Worth knowing where that decision is written down: the condition keeping
  Dependabot on 1.26.x was set by commenting on a pull request, so it lives in
  Dependabot's state and not in `.github/dependabot.yml`. Nothing in the tree
  records it, and lifting it means an `@dependabot unignore` comment rather than
  an edit here.

## [0.3.2] — 2026-08-21

Nothing in the proxy itself changed. The binary is rebuilt on Go 1.26.7, which
carries a single standard-library fix, and that fix is not reachable from this
program either. Hygiene, on the same reasoning as 0.3.1.

What did change is what CI enforces: the Actions are pinned to commit SHAs and
verified against the releases their comments name, and the third-party notice is
generated rather than assumed. None of it reaches the binary.

### Build

- **Rebuilt on Go 1.26.7.** Its one fix is
  [#80876](https://github.com/golang/go/issues/80876) in `net/http`, where a
  connection-level `ReadHeaderTimeout` deadline stayed armed after a connection
  was handed off to the unencrypted HTTP/2 server, so healthy long-lived h2c
  connections were cut at the timeout. It is a regression from the fix for
  [GO-2026-6089](https://pkg.go.dev/vuln/GO-2026-6089) that 0.3.1 picked up —
  the new code set a read deadline before sniffing for the HTTP/2 preface and
  only cleared it when `Server.ReadTimeout` was non-zero.

  The health server does set `ReadHeaderTimeout` (5s) and leaves `ReadTimeout`
  at zero, which is half of what the bug needs. The other half it never
  supplies: reaching the h2c path requires opting in with
  `Protocols.SetUnencryptedHTTP2(true)`, and `serveHealth` leaves `Protocols`
  at the default, so no connection is ever handed to the HTTP/2 server. Probes
  are unaffected.

- Go 1.27.0 was released the same day and was evaluated instead. It builds,
  vets and tests clean here, and none of its changes touch this code — no
  `encoding/json`, no TLS, no unix sockets, no `godebug` directives, and the
  SHA-1 scramble is untouched, since Go's SHA-1 restrictions have only ever
  applied to x509 signature verification and not to `crypto/sha1` itself. It
  was passed over only because there is no reason to run a two-day-old major
  when the fix on offer is not reachable anyway. 1.27 is for a later release.

  Dependabot's PR proposing `1.27.0-alpine` is closed with `ignore this minor
  version`, so it will keep offering 1.26.x patches and stop re-proposing the
  minor until that is lifted.

### Supply chain

Nothing here changes the binary either, but it changes what CI will let through.

- **Every Action is pinned to a commit SHA**, across both workflows, with the
  release it belongs to named in a comment beside it. They were floating on
  major tags, and a tag is a movable label its owner can repoint at any time.

- **`scripts/check-action-pins.sh` verifies those pins**, resolving each
  comment's tag upstream and failing when the SHA is not the commit that tag
  names. Without it the comment is the only part a reviewer reads and nothing
  makes the two agree — which is what makes a hash swapped for one taken from a
  fork look like a routine bump. Forks share object storage with their parent,
  so such a commit resolves under the real repository's URL too, and only
  resolving the tag tells them apart.

  It runs as its own job that every other job needs, and is a required check on
  `main`. Both halves matter: running it alongside the others would be too late,
  since a parallel job has already run its own `uses:` before the check can
  fail; and a job whose `needs:` failed reports as *skipped*, which branch
  protection counts as satisfied — so dropping it from the required list would
  let a failing pin check skip the rest into a green merge.

- **`THIRD-PARTY-NOTICES.md` records that there are no third-party
  dependencies** — `go.mod` declares no requires and there is no `go.sum` —
  and `scripts/gen-notices.sh --check` re-derives that on every run, so the
  claim cannot quietly become false the first time one is added.

- `go*.tar.gz` is ignored. A 62 MB toolchain tarball was sitting in the tree
  untracked and unignored, one `git add .` from entering history for good.

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

[0.3.4]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ralforion/mysql-old-password-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ralforion/mysql-old-password-proxy/releases/tag/v0.1.0
