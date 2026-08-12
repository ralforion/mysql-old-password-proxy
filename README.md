# mysql-old-password-proxy

A small proxy that lets modern MySQL clients read a legacy server whose account
still uses pre-4.1 (`mysql_old_password`) authentication.

```
client ──mysql_native_password──▶ proxy ──pre-4.1 auth──▶ legacy MySQL
            (TCP 3306)                      (TCP 3306)
```

Standard library only, no dependencies. The published image is a single static
binary on `scratch`.

## The problem

Modern drivers have dropped pre-4.1 authentication — MariaDB Connector/J in
3.x, MySQL Connector/J in 8.0, the `mysql` CLI from 5.7 — so a client meeting a
server that still holds a 16-byte password hash fails during plugin
negotiation:

```
Client does not support authentication protocol requested by server.
plugin type was = ''
```

```
ERROR 2059 (HY000): Authentication plugin 'mysql_old_password' cannot be loaded
```

**The proper fix is one statement on the legacy server**, storing a
`mysql_native_password` hash for a second account:

```sql
SET SESSION old_passwords = 0;
CREATE USER 'app'@'%' IDENTIFIED BY '...';
GRANT SELECT ON yourdb.* TO 'app'@'%';
```

Do that if you can, and delete this project. This proxy is for when you cannot:
no DBA access, a vendor-owned appliance, a server nobody is allowed to restart.

## How it works

Authentication is terminated **separately on each side**. The proxy speaks
`mysql_native_password` to its clients and pre-4.1 authentication to the legacy
server, then relays the post-authentication packet stream. It never parses SQL,
with two narrow and optional exceptions (below).

### The part that matters: capability flags

After authentication, MySQL's wire framing depends on the capabilities each side
negotiated. If a client negotiates `CLIENT_DEPRECATE_EOF` and the legacy server
does not, result sets are framed differently on the two halves and a byte copy
corrupts them *silently*.

So the proxy learns what the legacy server actually supports and offers clients
only the intersection with a set that excludes every framing-changing flag.
Never offered: `CLIENT_DEPRECATE_EOF`, `CLIENT_SESSION_TRACK`,
`CLIENT_QUERY_ATTRIBUTES`, `CLIENT_OPTIONAL_RESULTSET_METADATA` (framing),
`CLIENT_COMPRESS`, `CLIENT_ZSTD_COMPRESSION_ALGORITHM` (would need re-framing),
`CLIENT_SSL` (see [Security](#security)), `CLIENT_LOCAL_FILES` (turns the server
into a file-read request against the client), and `CLIENT_NO_SCHEMA` — which
changes no framing at all, but makes the server reject `database.table`
qualifiers, so carrying it breaks every schema-qualified query. Framing is not
the only way a capability can be unsafe to relay.

What the relay negotiates with the legacy server is what the *client*
negotiated, not the whole set: a capability enabled on one half only would make
statements mean different things on the two sides. `CLIENT_FOUND_ROWS` is the
plain example — an `UPDATE` would report matched rows to one side and changed
rows to the other.

Clients routinely *claim* flags the server never advertised — the mysql 8.0
client sends `CLIENT_DEPRECATE_EOF`, `CLIENT_SESSION_TRACK` and
`CLIENT_QUERY_ATTRIBUTES` to everything — and a real server ignores the surplus.
The proxy does the same, so what is in force is the intersection, which is safe
by construction. The invariant is then re-checked against the live backend
handshake before a byte is relayed; a backend restarted onto a different version
produces a clear error instead of corrupt results.

### Connection order

```
client handshake → client auth → backend dial + auth → OK to client → relay
```

Authenticating the client first means a Kubernetes probe, a port scan, or any
connection that never completes a handshake costs the legacy server nothing —
worth having when that server has a host cache that blocks an IP after enough
failed handshakes. The client's OK packet is withheld until the backend is up,
so a backend failure still surfaces as a clean error at connect time rather than
a hang. Backend capabilities come from a probe made at startup, which also
validates the credentials in your Secret at boot instead of on the first query.

### The three places SQL is touched

All are optional and all are off the SQL parser path — they are substring and
regexp checks on `COM_QUERY` payloads.

- **`-rewrite-utf8mb4`** (default on) rewrites `utf8mb4` → `utf8`. MySQL 5.0
  predates `utf8mb4` (added in 5.5) and drivers issue `SET NAMES utf8mb4`. It is
  a blunt replacement: a query carrying that literal *in data* is rewritten too.
  The same mapping is applied to the character set in the handshake.
- **`-rewrite-datetime-precision`** (default `auto`) replaces the
  `DATETIME_PRECISION` column with the literal `0` in `information_schema`
  queries, but only when the backend predates the column. That column arrived
  in MySQL 5.6 and in MariaDB 5.3, so without this, reading column metadata
  from a 5.0 or 5.1 server fails outright:

  ```
  Unknown column 'DATETIME_PRECISION' in 'field list'
  ```

  The gate matters in both directions. Against a server that *has* the column,
  substituting 0 would report every fractional-second column as having none:
  a `DATETIME(3)` would come back 19 wide instead of 23. So `auto` reads the
  version from the backend's handshake and only rewrites where it must —
  MySQL 5.5 is rewritten, MySQL 5.6 is not, and MariaDB is recognised behind
  the `5.5.5-` compatibility prefix it puts in front of its real version. A
  version string it cannot parse is left alone, so the failure is a loud
  `Unknown column` rather than quietly wrong metadata; `always` forces it.

  MariaDB Connector/J 3.x uses it in `DatabaseMetaData.getColumns()` to size
  temporal columns — `IF(DATETIME_PRECISION = 0, 19, CAST(20 + DATETIME_PRECISION
  as signed integer))` — so the substitution must be `0`, not `NULL`: `NULL`
  would poison the comparison and the arithmetic, and every temporal column
  would come back with a `NULL` size. Zero is also the truthful answer, since a
  server without fractional seconds has precision 0. Unlike the `utf8mb4`
  rewrite this one is narrow: it only fires on statements mentioning
  `information_schema`, and it respects identifier boundaries, so
  `MY_DATETIME_PRECISION_X` and a backtick-quoted `` `DATETIME_PRECISION` ``
  are left alone.

  Without it the proxy authenticates but no JDBC client can read a schema —
  which is most of the point.
- **`-fake-ok-regex`** (default off) answers matching statements with an OK
  packet without forwarding them. This is the escape hatch for driver session
  setup a legacy server rejects outright — `SET session_track_schema=1` and
  friends. Find them with `-log-queries`.

Everything else is forwarded verbatim with its original sequence id, including
statements larger than 16 MB, which the protocol splits across packets.

## Configuration

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:3306` | address to listen on for clients |
| `-backend` | *required* | legacy MySQL server `host:port` |
| `-backend-user` | *required* | username on the legacy server |
| `-frontend-user` | `-backend-user` | username clients must present |
| `-server-version` | `5.5.62-auth-relay` | version string advertised to clients |
| `-rewrite-utf8mb4` | `true` | rewrite `utf8mb4` to `utf8` |
| `-rewrite-datetime-precision` | `auto` | substitute `DATETIME_PRECISION` in `information_schema` queries: `auto`, `always` or `never` |
| `-fake-ok-regex` | *empty* | statements answered OK without reaching the backend |
| `-log-queries` | `false` | log every `COM_QUERY` (verbose; may expose data) |
| `-max-connections` | `0` | cap on concurrent sessions, each holding one backend connection (0 = unlimited) |
| `-frontend-password-from-backend` | `false` | let clients authenticate with the legacy password instead of a separate one |
| `-health-addr` | `:8081` | HTTP `/healthz` and `/readyz`; empty disables |
| `-dial-timeout` | `10s` | connecting to the backend |
| `-auth-timeout` | `30s` | completing authentication on either side |
| `-shutdown-timeout` | `30s` | waiting for in-flight connections on SIGTERM |
| `-version` | | print the version and exit |

Passwords come from the environment, **never flags** — flags are visible in the
process list and in `kubectl describe pod`:

| Variable | Meaning |
|---|---|
| `MYSQL_RELAY_BACKEND_PASSWORD` | the legacy server's password |
| `MYSQL_RELAY_FRONTEND_PASSWORD` | what clients must present to the proxy |

The two credentials are independent. Rotating the client-facing one does not
require touching the legacy server.

### Why there are two, and how to have one

The client's password cannot be forwarded to the legacy server, because the
proxy never receives it. MySQL authentication is challenge–response: a client
sends `SHA1(pw) XOR SHA1(scramble ‖ SHA1(SHA1(pw)))` against a random scramble,
which is one-way and salted per connection. The legacy side then needs a
different algorithm over the *raw* password bytes, against its own scramble. So
the proxy has to hold the legacy password, and has to run a complete, separate
authentication on each side. There is no pass-through arrangement.

What it can do is use the *same* password for both, so there is only one
credential to deploy:

```
-frontend-password-from-backend        # and leave MYSQL_RELAY_FRONTEND_PASSWORD unset
```

Consider what that costs before using it. The legacy password then lives in
every client's configuration, and a password on a server nobody can run
`ALTER USER` against is usually one nobody can rotate either — so a leak from a
client config becomes a problem you cannot fix. A separate frontend password
keeps the legacy one in exactly one place, and lets you rotate the
client-facing credential freely. Without the flag, a missing frontend password
is a startup error rather than a silent fallback.

`-server-version` is worth tuning. Claim too new and a driver assumes features
the legacy server lacks; too old and some drivers refuse to connect at all.

## Running it

### Docker

```sh
docker run -d --name mysql-old-password-proxy \
  -p 127.0.0.1:3306:3306 -p 127.0.0.1:8081:8081 \
  -e MYSQL_RELAY_BACKEND_PASSWORD='...' \
  -e MYSQL_RELAY_FRONTEND_PASSWORD='...' \
  ralforion/mysql-old-password-proxy:latest \
    -backend legacy-mysql.internal:3306 \
    -backend-user legacyaccount \
    -frontend-user app

mysql -h 127.0.0.1 -P 3306 --protocol TCP -u app -p
```

`deploy/compose.yaml` is the same thing as Compose.

### Kubernetes

`deploy/proxy.yaml` has a Deployment, Service, PodDisruptionBudget and a Secret
template. Replace `NAMESPACE`, `IMAGE_REF`, `LEGACY_HOST:PORT` and
`LEGACY_USER`, and create the Secret out of band rather than committing it:

```sh
kubectl -n mynamespace create secret generic mysql-old-password-proxy \
  --from-literal=backend-password='...' \
  --from-literal=frontend-password='...'

sed -e 's/NAMESPACE/mynamespace/g' \
    -e 's|IMAGE_REF|ralforion/mysql-old-password-proxy:v0.1.0|' \
    -e 's/LEGACY_HOST:PORT/legacy-mysql.internal:3306/' \
    -e 's/LEGACY_USER/legacyaccount/' \
    deploy/proxy.yaml | kubectl apply -f -
```

Clients then connect to
`mysql-old-password-proxy.<namespace>.svc.cluster.local:3306`.

Two things in that manifest are deliberate. Probes hit the HTTP port, not 3306,
so Kubernetes never opens a client connection — and so the pod stays *ready*
when the legacy server is down, because a clear MySQL error beats a connection
refused from an empty Service. And there is no CPU limit: throttling something
on the query path shows up as latency in every query behind it.

Note that MySQL authorises per `user@host`, and pods usually SNAT to their node
IP. With the proxy in place only the proxy's nodes need a grant on the legacy
server — which shrinks the grant surface rather than widening it.

## Concurrency and connections

Connections are handled **fully in parallel**: every client connection gets its
own goroutine and its own connection to the legacy server, and nothing is shared
between them. Queries on different connections never wait on each other.

There is **no connection pooling**, and that is deliberate rather than missing.
A MySQL session is stateful — session variables, the default schema, temporary
tables, an open transaction, prepared statements — so multiplexing several
client sessions onto one backend connection would leak that state between them.
One client session is one backend session.

The consequence is that N clients means N connections on the legacy server, and
an old server may have a small `max_connections` and other users besides you.
`-max-connections` bounds it: clients over the limit are refused with the same
"Too many connections" error MySQL itself sends, before the legacy server is
contacted at all. `/healthz` reports the live count.

## Footprint

The image is one static binary on `scratch`: no shell, no libc, no package
manager, nothing to pivot into and nothing to patch on a CVE treadmill. It runs
as uid 65532 with a read-only root filesystem and all capabilities dropped.
There are no third-party Go modules either, so the dependency surface is the
standard library.

A relayed connection costs on the order of tens of kilobytes — two goroutines,
two 4 KB read buffers, and a 32 KB copy buffer taken from a pool. Packets are
read into a per-session buffer that is reused, so a steady stream of queries
allocates nothing per packet. The manifest requests 10m CPU and 32Mi, with
`GOMEMLIMIT` set just under a 128Mi limit so the garbage collector sizes the
heap to the container rather than to the node.

The image holds exactly one file — the binary — as `docker export` will show;
everything else in a running container is mounted by the runtime.

| | Measured |
|---|---|
| binary | 5.7 MB |
| image | 8.2 MB |

## Building and testing

```sh
make build              # binary into bin/ (git-ignored; deploy/ is manifests only)
make test               # unit tests, with the race detector
make test-integration   # against real MySQL servers in Docker (slow)
make vet fmt cover
make help               # everything else
```

### Tests

`test/unit` needs neither network nor Docker. It pins the two password
algorithms against values measured on a real server (`OLD_PASSWORD()` prints
exactly the pre-4.1 hash), parses a captured 5.6 handshake, and runs the real
proxy in-process against a **fake MySQL 5.0-shaped backend** that greets with the
short handshake and asks for the old password with a bare `0xFE`. That fake
exists because the servers that need this proxy are usually 4.1–5.1, which
publish no official image.

`test/integration` runs the real binary against **two MySQL server images**, each
seeded with data and a genuine pre-4.1 account:

- **mysql:5.5** and **mysql:5.6** — the last servers that implement
  `mysql_old_password`; 5.7 removed it. They ask for it differently (5.6 needs
  `CLIENT_PLUGIN_AUTH`, and answers "Bad handshake" without it), which is
  exactly the kind of thing only a real server catches.

Against each, it runs stock **mysql 5.6**, **mysql 8.0** (which defaults to
`caching_sha2_password`, exercising the auth switch) and **mariadb 10.11**
clients in containers, plus a raw protocol client for what no CLI exposes:
prepared statements over the binary protocol, statements larger than 16 MB,
`COM_QUIT`, and result-set framing checked packet by packet. It also asserts the
premise — that a modern client *cannot* reach the account directly — and covers
a backend outage and recovery.

```sh
go test -tags integration -v -timeout 40m ./test/integration/...
```

## Releasing

Images are published to Docker Hub by GitHub Actions.

| Trigger | Tags |
|---|---|
| push to `main` | `:edge`, `:main-<sha>` |
| tag `v1.2.3` | `:1.2.3`, `:1.2`, `:1`, `:latest` |

```sh
make release TAG=v0.1.0
```

Nothing is published until the unit *and* integration suites pass in CI. Builds
are multi-arch (`linux/amd64`, `linux/arm64`) with provenance and an SBOM, and
the published image is smoke-tested by digest before the run is green.

Two repository secrets are required: `DOCKERHUB_USERNAME`, and `DOCKERHUB_TOKEN`
— an access token from Docker Hub → Account Settings → Personal access tokens
with Read & Write scope, never the account password. Override the image name
with a `DOCKERHUB_IMAGE` repository variable. To push to an internal mirror
instead:

```sh
make docker-push REGISTRY=registry.internal.example.com
```

Version comes from `git describe`, is stamped into the binary, and is reported
by `-version` and on `/healthz`. A plain `go build` with no stamp falls back to
the VCS revision the Go toolchain embeds.

## Security

- **Both hops are plaintext.** Pre-4.1 authentication is weak by construction
  and this changes nothing about that. Credentials and data cross the network in
  the clear, so run this on an internal network only, `ClusterIP` only, and
  record it as an accepted risk. `CLIENT_SSL` is never offered; a client
  requesting TLS is refused with a clear error rather than being silently
  downgraded.
- The proxy holds the legacy password **in plaintext** in memory. It has to:
  computing the pre-4.1 response requires the password itself, not a hash.
- Client passwords are compared in constant time.
- `LOAD DATA LOCAL INFILE` is not available through the proxy — the capability
  is never negotiated with the backend, so the legacy server cannot ask a client
  for a local file.
- `-log-queries` logs statements, which may contain data. It is for debugging a
  driver's session setup, not for leaving on.

## Limitations

- No TLS, on either side.
- No connection pooling: one client connection is one backend connection (see
  [Concurrency and connections](#concurrency-and-connections)).
- No compression (`CLIENT_COMPRESS` is deliberately never negotiated).
- One backend per process. Two legacy servers means two deployments.
- `-rewrite-utf8mb4` also rewrites the literal `utf8mb4` inside query data.
- The `information_schema` shim covers `DATETIME_PRECISION` only. It is the sole
  column MariaDB Connector/J 3.x's `getColumns()` needs that MySQL 5.0 lacks,
  but another driver, or another metadata call, may reach for something else
  — `GENERATION_EXPRESSION` (5.7) and `SRS_ID` (8.0) are the likely candidates.
  Find them with `-log-queries`.
- Statements over 16 MB are relayed but not inspected past their first chunk,
  so no rewrite applies to them.

## Licence

MIT. See [LICENSE](LICENSE).

The pre-4.1 scramble follows the algorithm as implemented in
[go-sql-driver/mysql](https://github.com/go-sql-driver/mysql) (MPL-2.0). It is
reimplemented rather than imported because that package's `scrambleOldPassword`,
`pwHash` and `myRnd` are unexported — it exports a `database/sql` driver, not
protocol helpers — and because a `database/sql` connection is the wrong shape
here anyway: the proxy has to keep the socket after authentication in order to
relay it. Keeping it in-tree is also what makes "standard library only" true.
