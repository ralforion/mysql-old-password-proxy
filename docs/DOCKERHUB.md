# mysql-old-password-proxy

Lets modern MySQL clients reach a legacy server that only accepts pre-4.1
(`mysql_old_password`) authentication.

```
client ──mysql_native_password──▶ proxy ──pre-4.1 auth──▶ legacy MySQL
```

Source, design notes and full documentation:
**https://github.com/ralforion/mysql-old-password-proxy**

## The problem it solves

Modern drivers dropped pre-4.1 authentication — MariaDB Connector/J in 3.x,
MySQL Connector/J in 8.0, the `mysql` CLI from 5.7 — so connecting to a server
that still holds a 16-byte password hash fails during plugin negotiation:

```
Client does not support authentication protocol requested by server.
plugin type was = ''

ERROR 2059 (HY000): Authentication plugin 'mysql_old_password' cannot be loaded
```

If you can run `ALTER USER` on the legacy server, do that instead — this proxy
is for when you cannot.

## Tags

| Tag | What it is |
|---|---|
| `latest`, `1.2.3`, `1.2`, `1` | released versions |
| `edge` | the tip of `main` |
| `main-<sha>` | a specific commit |

Pin a version or a digest in production. Built for `linux/amd64` and
`linux/arm64`, with provenance and an SBOM.

## Quick start

```sh
docker run -d --name mysql-old-password-proxy \
  -p 127.0.0.1:3306:3306 \
  -e MYSQL_RELAY_BACKEND_PASSWORD='legacy-password' \
  -e MYSQL_RELAY_FRONTEND_PASSWORD='what-clients-will-use' \
  ralforion/mysql-old-password-proxy:latest \
    -backend legacy-mysql.internal:3306 \
    -backend-user legacyaccount \
    -frontend-user app
```

Then point any modern client at the proxy:

```sh
mysql -h 127.0.0.1 -P 3306 --protocol TCP -u app -p
```

## Configuration

Passwords come from the environment — never flags, which are visible in the
process list and in `kubectl describe pod`:

| Variable | Meaning |
|---|---|
| `MYSQL_RELAY_BACKEND_PASSWORD` | the legacy server's password |
| `MYSQL_RELAY_FRONTEND_PASSWORD` | what clients present to the proxy |

The two credentials are independent: rotating the client-facing one does not
require touching the legacy server.

| Flag | Default | Meaning |
|---|---|---|
| `-backend` | *required* | legacy MySQL server `host:port` |
| `-backend-user` | *required* | username on the legacy server |
| `-frontend-user` | `-backend-user` | username clients must present |
| `-listen` | `:3306` | address to listen on |
| `-health-addr` | `:8081` | HTTP `/healthz` and `/readyz` |
| `-server-version` | `5.5.62-auth-relay` | version advertised to clients |
| `-rewrite-utf8mb4` | `true` | rewrite `utf8mb4` → `utf8` (MySQL 5.0 has neither) |
| `-max-connections` | `0` | cap on concurrent sessions (0 = unlimited) |
| `-fake-ok-regex` | *empty* | answer matching statements OK without forwarding |
| `-log-queries` | `false` | log every query (verbose; may expose data) |

`docker run ... ralforion/mysql-old-password-proxy -help` lists them all.

## Image

One static binary on `scratch` — no shell, no libc, no package manager, ~6 MB.
It runs as uid 65532 and needs no writable filesystem, so:

```sh
docker run --read-only --cap-drop ALL --security-opt no-new-privileges:true ...
```

A relayed connection costs on the order of tens of kilobytes, so 128 MB is a
generous limit. Set `GOMEMLIMIT` just under it if you impose one.

## Health

`/healthz` and `/readyz` on port 8081 report the version, the backend's
capability flags and the number of live connections. They deliberately stay
healthy when the legacy server is down, so clients get a clear MySQL error
rather than a connection refused.

## Caveats

- **Both hops are plaintext.** No TLS on either side. Internal networks only.
- The proxy holds the legacy password in plaintext in memory — computing a
  pre-4.1 response requires the password, not a hash.
- No pooling: one client connection is one backend connection.
- `LOAD DATA LOCAL INFILE` and compression are not available through the proxy,
  by design.

## Licence

MIT.
