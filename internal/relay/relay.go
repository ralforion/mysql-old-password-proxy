// Package relay implements the proxy: it terminates authentication separately
// on each side, speaking mysql_native_password to its clients and pre-4.1
// ("mysql_old_password") authentication to a legacy server, then relays the
// post-authentication packet stream.
//
// # The part that matters: capability flags
//
// After authentication, MySQL's wire framing depends on the capabilities each
// side negotiated. If a client negotiates CLIENT_DEPRECATE_EOF and the legacy
// server does not, result sets are framed differently on the two halves of the
// relay and a byte copy silently corrupts them. The relay therefore learns what
// the legacy server actually supports and offers clients only the intersection
// with FramingSafe, a set that excludes every flag known to alter framing. The
// invariant is re-checked against the live backend handshake before a single
// byte is relayed — see CheckCapabilities.
//
// # Connection order
//
// The backend's capabilities come from a probe connection made at startup, so
// the per-connection order is:
//
//	client handshake -> client auth -> backend dial+auth -> OK to client -> relay
//
// Authenticating the client first means a Kubernetes TCP probe, a port scan or
// any other connection that never completes a handshake costs the legacy server
// nothing, and it lets the relay pass the client's requested default schema
// straight through in the backend handshake. Because the client's OK packet is
// withheld until the backend is up, a backend failure is still reported as a
// clean ERR at connect time rather than a hang.
//
// If the startup probe has not succeeded yet (backend down at boot), the first
// connection probes the backend first instead, at the cost of one extra
// backend connection.
package relay

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ralforion/mysql-old-password-proxy/internal/mysqlwire"
)

// FramingSafe is the set of capabilities the relay is willing to carry end to
// end: those that neither change post-authentication framing nor change what a
// statement means. The offer made to clients is masked by the backend's flags,
// so both sides always negotiate the same subset of it.
//
// CLIENT_NO_SCHEMA is the reason the second half of that sentence is there. It
// does not touch framing at all, so an earlier version of this list included
// it — but it tells the server to reject database.table qualifiers, which
// quietly broke every schema-qualified query through the proxy. Framing is not
// the only way a capability can be unsafe to carry.
//
// Deliberately ABSENT: CLIENT_DEPRECATE_EOF and CLIENT_SESSION_TRACK (they
// change result-set framing), CLIENT_QUERY_ATTRIBUTES and
// CLIENT_OPTIONAL_RESULTSET_METADATA (they change COM_QUERY and result-set
// framing), CLIENT_COMPRESS and CLIENT_ZSTD_COMPRESSION_ALGORITHM (would need
// decompressing to re-frame), CLIENT_SSL (the relay is plaintext on both
// sides — see the README), CLIENT_LOCAL_FILES (LOCAL INFILE turns the server
// into a file-read request against the client).
const FramingSafe = mysqlwire.CapLongPassword | mysqlwire.CapFoundRows |
	mysqlwire.CapLongFlag | mysqlwire.CapConnectWithDB |
	mysqlwire.CapIgnoreSpace | mysqlwire.CapProtocol41 | mysqlwire.CapTransactions |
	mysqlwire.CapSecureConnection | mysqlwire.CapMultiStatements |
	mysqlwire.CapMultiResults | mysqlwire.CapPSMultiResults

// FramingRelevant is every capability that changes the post-authentication byte
// stream. A client that negotiates one of these without the relay having
// negotiated it with the backend too would read a stream framed the other way,
// so such a connection is refused rather than silently corrupted.
const FramingRelevant = mysqlwire.CapProtocol41 | mysqlwire.CapCompress |
	mysqlwire.CapZstd | mysqlwire.CapLocalFiles | mysqlwire.CapMultiStatements |
	mysqlwire.CapMultiResults | mysqlwire.CapPSMultiResults |
	mysqlwire.CapSessionTrack | mysqlwire.CapDeprecateEOF |
	mysqlwire.CapOptionalMetadata | mysqlwire.CapQueryAttributes

// Config is the relay's complete configuration. Passwords are values here
// rather than flags on purpose: flags are visible in the process list and in
// `kubectl describe pod`.
type Config struct {
	Backend      string // legacy server host:port
	BackendUser  string
	BackendPass  string
	FrontendUser string
	FrontendPass string

	ServerVersion  string         // version string advertised to clients
	RewriteUTF8MB4 bool           // rewrite utf8mb4 to utf8 in COM_QUERY
	RewriteDTP     DTPMode        // when to replace DATETIME_PRECISION in information_schema queries
	FakeOK         *regexp.Regexp // statements answered OK without reaching the backend
	LogQueries     bool

	DialTimeout time.Duration
	AuthTimeout time.Duration

	// MaxConnections bounds how many client sessions may be live at once, and
	// therefore how many connections the legacy server can be asked to hold:
	// there is no pooling, one client session is one backend session. Zero
	// means unlimited. Clients over the limit get a "Too many connections"
	// error, which is the same thing MySQL itself would say — better than
	// exhausting max_connections on a server that may have other users.
	MaxConnections int

	Logger *log.Logger
}

func (c *Config) validate() error {
	switch {
	case c.Backend == "":
		return errors.New("backend address is required")
	case c.BackendUser == "":
		return errors.New("backend user is required")
	case c.BackendPass == "":
		return errors.New("backend password is required")
	case c.FrontendPass == "":
		return errors.New("frontend password is required")
	}
	if c.FrontendUser == "" {
		c.FrontendUser = c.BackendUser
	}
	if c.ServerVersion == "" {
		c.ServerVersion = "5.5.62-auth-relay"
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = 30 * time.Second
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	return nil
}

// Server relays client connections to one legacy MySQL server.
type Server struct {
	cfg Config

	// caps caches the capability flags the legacy server advertised. The bit
	// above the low 32 marks the value as known, so that a server advertising
	// nothing is still distinguishable from "not learned yet".
	caps   atomic.Uint64
	connID atomic.Uint32
	active sync.WaitGroup
	live   atomic.Int64 // sessions currently being relayed

	// loggedVersion keeps the shim's reasoning to one line per distinct
	// backend version, rather than one per connection.
	loggedVersion atomic.Value
}

const capsKnownBit = 1 << 32

// New validates cfg and returns a Server. It does not touch the network.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg}, nil
}

// Config returns the effective configuration, with defaults applied.
func (s *Server) Config() Config { return s.cfg }

// LiveConnections is the number of client sessions currently being relayed,
// each of which holds one connection to the legacy server.
func (s *Server) LiveConnections() int { return int(s.live.Load()) }

func (s *Server) storeBackendCaps(c uint32) { s.caps.Store(uint64(c) | capsKnownBit) }

// BackendCaps returns the cached backend capabilities and whether they have
// been learned yet.
func (s *Server) BackendCaps() (uint32, bool) {
	v := s.caps.Load()
	return uint32(v), v&capsKnownBit != 0
}

// Serve accepts connections until ln is closed, handling each in its own
// goroutine. It returns once the listener stops accepting; use Wait to drain
// in-flight sessions afterwards.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if max := s.cfg.MaxConnections; max > 0 && s.live.Load() >= int64(max) {
			mysqlwire.WritePacket(c, mysqlwire.ErrPacket(1040, "08004",
				fmt.Sprintf("Too many connections (the relay is limited to %d)", max)), 0)
			c.Close()
			s.cfg.Logger.Printf("refused a connection from %s: at the %d-connection limit",
				c.RemoteAddr(), max)
			continue
		}
		s.active.Add(1)
		s.live.Add(1)
		go func(c net.Conn, id uint32) {
			defer s.active.Done()
			defer s.live.Add(-1)
			defer c.Close()
			start := time.Now()
			if err := s.handle(c, id); err != nil && !errors.Is(err, io.EOF) {
				s.cfg.Logger.Printf("conn %d (%s): %v [%s]",
					id, c.RemoteAddr(), err, time.Since(start).Round(time.Millisecond))
			}
		}(c, s.connID.Add(1))
	}
}

// Wait blocks until every in-flight session has finished or ctx is done. It
// reports whether the drain completed.
func (s *Server) Wait(ctx context.Context) bool {
	done := make(chan struct{})
	go func() { s.active.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// ProbeBackend authenticates against the legacy server and disconnects
// cleanly. It validates the configured credentials and primes the capability
// cache, so the ordinary path needs only one backend connection per session.
func (s *Server) ProbeBackend() (uint32, error) {
	conn, caps, err := s.dialBackend("", defaultCharset, 0)
	if err != nil {
		return 0, err
	}
	conn.quit()
	return caps, nil
}

// ProbeBackendUntilOK retries ProbeBackend until it succeeds or ctx is done,
// logging each failure. It is meant to run in the background at startup.
func (s *Server) ProbeBackendUntilOK(ctx context.Context, every time.Duration) {
	for attempt := 1; ; attempt++ {
		caps, err := s.ProbeBackend()
		if err == nil {
			s.cfg.Logger.Printf("backend probe ok: server capabilities 0x%08x, relaying with 0x%08x",
				caps, caps&FramingSafe)
			return
		}
		s.cfg.Logger.Printf("backend probe failed (attempt %d): %v", attempt, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// Handle runs one client session on an already-accepted connection. Serve does
// this for every connection it accepts; it is exported for callers that manage
// their own listener.
func (s *Server) Handle(client net.Conn) error {
	return s.handle(client, s.connID.Add(1))
}

// handle greets and authenticates the client, dials and authenticates the
// backend, then relays until either end closes.
func (s *Server) handle(client net.Conn, id uint32) error {
	caps, known := s.BackendCaps()
	if !known {
		// The startup probe has not succeeded yet. Learn the capabilities from
		// a dedicated backend connection rather than guessing at the offer.
		c, err := s.ProbeBackend()
		if err != nil {
			s.writeEarlyErr(client, "relay could not reach the legacy server: "+err.Error())
			return fmt.Errorf("backend probe: %w", err)
		}
		caps = c
	}

	client.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))
	fe, err := s.authenticateClient(client, id, caps)
	if err != nil {
		return fmt.Errorf("frontend auth: %w", err)
	}

	backend, serverCaps, err := s.dialBackend(fe.db, fe.charset, EffectiveCaps(fe.caps, fe.offered))
	if err != nil {
		fe.writeErr(1045, "28000", "relay could not reach the legacy server: "+err.Error())
		return fmt.Errorf("backend: %w", err)
	}
	defer backend.Close()

	if err := CheckCapabilities(fe.caps, fe.offered, serverCaps); err != nil {
		fe.writeErr(1105, "HY000", "relay: "+err.Error())
		return err
	}

	// Only now is the session real, so acknowledge the client's login.
	if err := fe.writeOK(); err != nil {
		return err
	}
	client.SetDeadline(time.Time{})
	backend.SetDeadline(time.Time{})
	s.cfg.Logger.Printf("conn %d (%s): authenticated as %q, schema %q, capabilities in force 0x%08x (client asked 0x%08x), backend 0x%08x; relaying",
		id, client.RemoteAddr(), fe.user, fe.db,
		EffectiveCaps(fe.caps, fe.offered), fe.caps, serverCaps&FramingSafe)

	return s.relay(fe, backend)
}

// writeEarlyErr reports a failure to a client that has not been greeted yet.
// MySQL itself does this for ER_HOST_IS_BLOCKED, so clients handle it.
func (s *Server) writeEarlyErr(w io.Writer, msg string) {
	mysqlwire.WritePacket(w, mysqlwire.ErrPacket(1045, "28000", msg), 0)
}

// EffectiveCaps is the capability set actually in force on a connection: what
// the client asked for, intersected with what the server offered.
//
// The intersection matters. Stock MySQL clients set bits the server never
// advertised — the mysql 8.0 client sends CLIENT_DEPRECATE_EOF,
// CLIENT_SESSION_TRACK and CLIENT_QUERY_ATTRIBUTES to every server — and a real
// server ignores the surplus rather than refusing the connection. The relay
// does the same, so the framing both ends use is the intersection, which by
// construction excludes everything absent from the relay's offer.
func EffectiveCaps(clientCaps, offered uint32) uint32 { return clientCaps & offered }

// shimDatetimePrecision decides whether this backend needs the
// DATETIME_PRECISION substitution, and says so in the log the first time it
// sees a given version — the reasoning is otherwise invisible, and it is the
// first thing to check when metadata reads misbehave.
func (s *Server) shimDatetimePrecision(version string) bool {
	switch s.cfg.RewriteDTP {
	case DTPNever:
		return false
	case DTPAlways:
		return true
	}
	has, recognised := BackendHasDatetimePrecision(version)
	if s.loggedVersion.Swap(version) != version {
		switch {
		case !recognised:
			s.cfg.Logger.Printf("backend version %q not recognised; assuming it has DATETIME_PRECISION and leaving metadata queries alone. "+
				"If they fail with \"Unknown column\", pass -rewrite-datetime-precision=always", version)
		case has:
			s.cfg.Logger.Printf("backend %q has DATETIME_PRECISION; metadata queries are relayed unchanged", version)
		default:
			s.cfg.Logger.Printf("backend %q predates DATETIME_PRECISION; substituting 0 for it in information_schema queries", version)
		}
	}
	return !has
}

// CheckCapabilities enforces the invariant the whole design rests on: the
// capabilities in force with the client must not include a framing-relevant
// flag the relay did not also negotiate with the backend.
//
// offered is what the relay advertised to the client, which was derived from
// the backend capabilities cached at the time. serverCaps is what the backend
// advertised on this connection. The check therefore fires when, and only when,
// the backend has changed its capabilities since that cache was filled — a
// restart onto a different version — which is exactly the case where a byte
// copy would corrupt result sets.
func CheckCapabilities(clientCaps, offered, serverCaps uint32) error {
	effective := EffectiveCaps(clientCaps, offered)
	used := serverCaps & FramingSafe
	if bad := effective & FramingRelevant &^ used; bad != 0 {
		return fmt.Errorf("capability mismatch: this session negotiated 0x%08x which the legacy server does not support (client 0x%08x, offered 0x%08x, server 0x%08x)",
			bad, clientCaps, offered, serverCaps)
	}
	return nil
}

// ---------------------------------------------------------------- backend ---

// backendConn is an authenticated connection to the legacy server. It carries
// the bufio.Reader used during the handshake because that reader may already
// hold bytes belonging to the relayed stream.
type backendConn struct {
	net.Conn
	r *bufio.Reader

	version string // as the server reported it in its greeting
	shimDTP bool   // whether this server needs the DATETIME_PRECISION shim
}

func (c *backendConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// quit ends the session politely, so the server does not count an aborted
// connection against its host cache. Errors are ignored: the connection is
// being discarded either way.
func (c *backendConn) quit() {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	mysqlwire.WritePacket(c.Conn, []byte{mysqlwire.ComQuit}, 0)
	c.Close()
}

// authPhase are the capabilities that matter only while authenticating. They
// follow what the backend offers rather than what a client asked for: they say
// nothing about the session that follows.
const authPhase = mysqlwire.CapProtocol41 | mysqlwire.CapSecureConnection | mysqlwire.CapPluginAuth

// dialBackend connects to the legacy server and completes authentication,
// including the pre-4.1 fallback. db, if non-empty, becomes the session's
// default schema, and charset its default character set. It returns the live
// connection and the capability flags the server advertised.
//
// clientCaps is what the client negotiated, so that the session the relay opens
// on the far side behaves the same way as the one the client believes it has.
// CLIENT_FOUND_ROWS is the clearest example: negotiated on one half only, an
// UPDATE would report matched rows to one side and changed rows to the other.
// Zero means no client — the startup probe — and negotiates only what is needed
// to authenticate.
func (s *Server) dialBackend(db string, charset byte, clientCaps uint32) (*backendConn, uint32, error) {
	conn, err := net.DialTimeout("tcp", s.cfg.Backend, s.cfg.DialTimeout)
	if err != nil {
		return nil, 0, err
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))

	r := bufio.NewReader(conn)
	payload, _, err := mysqlwire.ReadPacket(r)
	if err != nil {
		return nil, 0, fmt.Errorf("read handshake: %w", err)
	}
	if mysqlwire.IsErr(payload) {
		// The server refused before greeting us — typically ER_HOST_IS_BLOCKED
		// (1129) after too many failed handshakes from this source address.
		return nil, 0, fmt.Errorf("backend refused the connection: %s", mysqlwire.ErrText(payload))
	}

	serverCaps, scramble, err := mysqlwire.ParseServerHandshake(payload)
	if err != nil {
		return nil, 0, err
	}
	version := mysqlwire.ParseServerVersion(payload)
	s.storeBackendCaps(serverCaps)
	if serverCaps&mysqlwire.CapProtocol41 == 0 {
		return nil, 0, errors.New("backend does not support the 4.1 protocol; this relay cannot speak the 3.23 handshake")
	}

	// CLIENT_PLUGIN_AUTH is a connection-phase flag: it changes nothing about
	// how the relayed stream is framed, and a server that advertises it
	// requires it. MySQL 5.6 rejects a handshake response without it —
	// "Bad handshake" — even for a pre-4.1 account. MySQL 5.0 does not
	// advertise it, so nothing is claimed there.
	caps := serverCaps & ((clientCaps & FramingSafe) | authPhase)
	if db == "" {
		caps &^= mysqlwire.CapConnectWithDB
	} else if caps&mysqlwire.CapConnectWithDB == 0 {
		return nil, 0, errors.New("backend does not support CLIENT_CONNECT_WITH_DB")
	}

	// First attempt: 4.1-style native auth. A server holding a pre-4.1 password
	// hash for this account answers with 0xFE ("switch auth"), which is the
	// case this relay exists to handle.
	// The relay claims mysql_native_password and lets the server ask it to
	// switch, which is what a pre-4.1 account makes it do.
	resp := mysqlwire.BuildHandshakeResponse41(caps, BackendCharset(charset, s.cfg.RewriteUTF8MB4),
		s.cfg.BackendUser, mysqlwire.NativePassword(scramble, s.cfg.BackendPass), db,
		mysqlwire.NativePasswordPlugin)
	if err := mysqlwire.WritePacket(conn, resp, 1); err != nil {
		return nil, 0, err
	}

	payload, seq, err := mysqlwire.ReadPacket(r)
	if err != nil {
		return nil, 0, fmt.Errorf("read auth result: %w", err)
	}

	if mysqlwire.IsAuthSwitch(payload) {
		// MySQL 5.0 sends a bare 0xFE and means "old password, reuse the
		// scramble you already have". 5.5+ sends a full AuthSwitchRequest
		// naming the plugin and carrying a fresh scramble.
		plugin, newScramble := mysqlwire.ParseAuthSwitch(payload)
		if plugin == "" {
			plugin, newScramble = mysqlwire.OldPasswordPlugin, scramble
		}
		var authResp []byte
		switch plugin {
		case mysqlwire.OldPasswordPlugin:
			// The pre-4.1 response is a NUL-terminated string.
			authResp = append(mysqlwire.ScrambleOldPassword(newScramble, s.cfg.BackendPass), 0x00)
		case mysqlwire.NativePasswordPlugin:
			authResp = mysqlwire.NativePassword(newScramble, s.cfg.BackendPass)
		default:
			return nil, 0, fmt.Errorf("backend requested unsupported auth plugin %q", plugin)
		}
		if err := mysqlwire.WritePacket(conn, authResp, seq+1); err != nil {
			return nil, 0, err
		}
		payload, _, err = mysqlwire.ReadPacket(r)
		if err != nil {
			return nil, 0, fmt.Errorf("read old-auth result: %w", err)
		}
	}

	switch {
	case len(payload) == 0:
		return nil, 0, errors.New("empty auth response from backend")
	case mysqlwire.IsOK(payload):
		ok = true
		return &backendConn{
			Conn:    conn,
			r:       r,
			version: version,
			shimDTP: s.shimDatetimePrecision(version),
		}, serverCaps, nil
	case mysqlwire.IsErr(payload):
		return nil, 0, fmt.Errorf("backend rejected login: %s", mysqlwire.ErrText(payload))
	default:
		return nil, 0, fmt.Errorf("unexpected auth response 0x%02x from backend", payload[0])
	}
}

// defaultCharset is utf8_general_ci, used for connections made without a
// client to inherit a character set from.
const defaultCharset = 33

// BackendCharset picks the character set sent in the handshake to the legacy
// server. MySQL 5.0 predates utf8mb4 (5.5) and rejects its collation ids
// outright, so those are mapped down to utf8_general_ci when rewriting is on;
// anything else the client asked for is passed through.
func BackendCharset(clientCharset byte, rewriteUTF8MB4 bool) byte {
	const utf8GeneralCI = 33
	if !rewriteUTF8MB4 {
		return clientCharset
	}
	switch {
	case clientCharset == 45 || clientCharset == 46: // utf8mb4_general_ci / utf8mb4_bin
		return utf8GeneralCI
	case clientCharset >= 224: // the utf8mb4_* collations added in 5.5 and later
		return utf8GeneralCI
	}
	return clientCharset
}

// --------------------------------------------------------------- frontend ---

// frontendConn is an authenticated client connection, plus everything learned
// during its handshake that the backend half needs.
type frontendConn struct {
	net.Conn
	r       *bufio.Reader
	id      uint32
	user    string
	db      string
	charset byte
	caps    uint32 // what the client sent in its handshake response
	offered uint32 // what the relay advertised to it
	seq     byte   // sequence id of the last packet received from the client
}

func (c *frontendConn) writeOK() error {
	return mysqlwire.WritePacket(c.Conn, mysqlwire.OKPacket(), c.seq+1)
}

func (c *frontendConn) writeErr(code uint16, state, msg string) {
	mysqlwire.WritePacket(c.Conn, mysqlwire.ErrPacket(code, state, msg), c.seq+1)
}

// authenticateClient performs the server side of the handshake, offering only
// capabilities the backend also supports.
func (s *Server) authenticateClient(client net.Conn, id, backendCaps uint32) (*frontendConn, error) {
	scramble, err := mysqlwire.NewScramble()
	if err != nil {
		return nil, err
	}

	caps := (backendCaps & FramingSafe) | mysqlwire.CapProtocol41 |
		mysqlwire.CapSecureConnection | mysqlwire.CapPluginAuth

	greeting := mysqlwire.BuildServerHandshake(s.cfg.ServerVersion, id, caps, scramble)
	if err := mysqlwire.WritePacket(client, greeting, 0); err != nil {
		return nil, err
	}

	r := bufio.NewReader(client)
	payload, seq, err := mysqlwire.ReadPacket(r)
	if err != nil {
		return nil, fmt.Errorf("read handshake response: %w", err)
	}
	fe := &frontendConn{Conn: client, r: r, id: id, seq: seq, offered: caps}

	hr, err := mysqlwire.ParseHandshakeResponse41(payload)
	if err != nil {
		fe.writeErr(1043, "08S01", "relay: "+err.Error())
		return nil, err
	}
	fe.user, fe.db, fe.caps, fe.charset = hr.User, hr.DB, hr.Caps, hr.Charset

	authResp := hr.AuthResp
	if hr.Plugin != "" && hr.Plugin != mysqlwire.NativePasswordPlugin {
		// A client that offered another plugin first — a MySQL 8 client
		// defaults to caching_sha2_password — is asked to switch.
		req := mysqlwire.AuthSwitchRequest(mysqlwire.NativePasswordPlugin, scramble)
		if err := mysqlwire.WritePacket(client, req, seq+1); err != nil {
			return nil, err
		}
		if authResp, seq, err = mysqlwire.ReadPacket(r); err != nil {
			return nil, fmt.Errorf("read auth switch response: %w", err)
		}
		fe.seq = seq
	}

	expected := mysqlwire.NativePassword(scramble, s.cfg.FrontendPass)
	if fe.user != s.cfg.FrontendUser || subtle.ConstantTimeCompare(authResp, expected) != 1 {
		fe.writeErr(1045, "28000", fmt.Sprintf("Access denied for user '%s' (relay)", fe.user))
		return nil, fmt.Errorf("access denied for %q", fe.user)
	}
	return fe, nil
}

// ------------------------------------------------------------------ relay ---

// relay copies packets in both directions until either side closes.
//
// Backend to client is a straight byte copy: the relay never needs to touch
// server responses, and both sides negotiated the same framing flags.
//
// Client to backend is packet-aware only so COM_QUERY can be inspected. Unless
// FakeOK matches, every packet is forwarded with its original sequence id, so
// numbering is untouched.
func (s *Server) relay(client *frontendConn, backend *backendConn) error {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := copyBufPool.Get().(*[]byte)
		io.CopyBuffer(client.Conn, backend, *buf)
		copyBufPool.Put(buf)
		client.Close()
	}()

	err := s.clientToBackend(client, backend)

	backend.Close()
	wg.Wait()
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) clientToBackend(client *frontendConn, backend *backendConn) error {
	// continued tracks whether the previous packet carried a full 16 MB
	// payload, which means this one is its continuation and starts with data
	// rather than a command byte.
	continued := false
	// Each packet is forwarded before the next is read, so one buffer serves
	// the whole session: an idle-then-busy connection settles at the size of
	// its largest statement rather than allocating per packet.
	var buf []byte
	for {
		payload, seq, err := mysqlwire.ReadPacketInto(client.r, buf)
		if err != nil {
			return err
		}
		buf = payload[:cap(payload)]
		split := len(payload) == mysqlwire.MaxPayload
		isCommand := !continued
		continued = split

		// A statement split across packets is left alone: rewriting the first
		// chunk would change its length and break the continuation.
		if isCommand && !split && len(payload) > 0 && payload[0] == mysqlwire.ComQuery {
			q := string(payload[1:])
			if s.cfg.LogQueries {
				s.cfg.Logger.Printf("conn %d: query: %s", client.id, truncate(q, 500))
			}
			if s.cfg.RewriteUTF8MB4 {
				if nq := RewriteUTF8MB4(q); nq != q {
					q = nq
					payload = append([]byte{mysqlwire.ComQuery}, q...)
				}
			}
			if backend.shimDTP {
				if nq := RewriteDatetimePrecision(q); nq != q {
					q = nq
					payload = append([]byte{mysqlwire.ComQuery}, q...)
				}
			}
			if s.cfg.FakeOK != nil && s.cfg.FakeOK.MatchString(q) {
				s.cfg.Logger.Printf("conn %d: answering OK without forwarding: %s", client.id, truncate(q, 200))
				if err := mysqlwire.WritePacket(client.Conn, mysqlwire.OKPacket(), seq+1); err != nil {
					return err
				}
				continue
			}
		}

		if err := mysqlwire.WritePacket(backend.Conn, payload, seq); err != nil {
			return err
		}
		if isCommand && len(payload) > 0 && payload[0] == mysqlwire.ComQuit {
			return nil
		}
	}
}

// copyBufPool holds the buffers used to relay backend responses. A MySQL
// response is a stream of packets the relay never inspects, so it is copied
// 32 KB at a time; pooling keeps a burst of new connections from allocating a
// fresh buffer each.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// asciiFold lowercases the ASCII letters in q and leaves every other byte
// exactly as it is, so the result is always the same length as the input.
//
// strings.ToLower cannot be used for this. It folds by Unicode rules, which
// change byte lengths: U+212A KELVIN SIGN is three bytes and lowercases to a
// one-byte "k". Indexing the original query with offsets taken from a folded
// copy then reads out of bounds — a query mixing such a rune with a rewrite
// trigger used to panic the process. The keywords being matched are ASCII, so
// ASCII folding loses nothing.
func asciiFold(q string) string {
	b := []byte(q)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// RewriteUTF8MB4 downgrades utf8mb4 to utf8. MySQL 5.0 predates utf8mb4 (added
// in 5.5), and modern drivers issue session setup such as "SET NAMES utf8mb4"
// that such a server rejects outright.
//
// This is a blunt substring replacement: a query carrying the literal text
// "utf8mb4" in DATA would also be rewritten. Turn it off if that matters for
// the workload.
func RewriteUTF8MB4(q string) string {
	const needle = "utf8mb4"
	lower := asciiFold(q)
	if !strings.Contains(lower, needle) {
		return q
	}
	var b strings.Builder
	b.Grow(len(q))
	for i := 0; i < len(q); {
		if strings.HasPrefix(lower[i:], needle) {
			i += len(needle)
			// A collation suffix has to be checked, not just renamed: utf8mb4
			// gained collations that utf8 never had, and utf8_0900_ai_ci does
			// not exist on any server.
			if suffix, next, ok := collationSuffix(lower, i); ok {
				if utf8mb3Collations[suffix] {
					b.WriteString("utf8") // the suffix is copied as it stands
				} else {
					b.WriteString("utf8_general_ci")
					i = next
				}
				continue
			}
			b.WriteString("utf8")
			continue
		}
		b.WriteByte(q[i])
		i++
	}
	return b.String()
}

// collationSuffix reads the "_general_ci" part following a charset name in the
// already-folded lower, starting at i. ok is false when what follows is not a
// collation suffix at all — a bare "utf8mb4" in SET NAMES, say.
func collationSuffix(lower string, i int) (suffix string, next int, ok bool) {
	if i >= len(lower) || lower[i] != '_' {
		return "", i, false
	}
	j := i + 1
	for j < len(lower) && (lower[j] == '_' ||
		(lower[j] >= 'a' && lower[j] <= 'z') ||
		(lower[j] >= '0' && lower[j] <= '9')) {
		j++
	}
	if j == i+1 {
		return "", i, false
	}
	return lower[i+1 : j], j, true
}

// utf8mb3Collations are the collations the old utf8 character set actually has,
// measured on MySQL 5.5 — minus sinhala_ci and general_mysql500_ci, which
// arrived in 5.5 and 5.1 and so cannot be assumed on the 5.0 servers this proxy
// is aimed at.
//
// A utf8mb4 collation outside this set is mapped to utf8_general_ci rather than
// renamed. The renaming is what a plain substitution would do, and it invents
// collations that have never existed: utf8mb4_0900_ai_ci, the default in MySQL
// 8.0, would become utf8_0900_ai_ci and be rejected outright. Substituting a
// collation the server does have changes sort order for the session, which is a
// smaller cost than a connection that cannot be opened.
var utf8mb3Collations = map[string]bool{
	"general_ci": true, "bin": true, "unicode_ci": true,
	"czech_ci": true, "danish_ci": true, "esperanto_ci": true,
	"estonian_ci": true, "hungarian_ci": true, "icelandic_ci": true,
	"latvian_ci": true, "lithuanian_ci": true, "persian_ci": true,
	"polish_ci": true, "romanian_ci": true, "roman_ci": true,
	"slovak_ci": true, "slovenian_ci": true, "spanish2_ci": true,
	"spanish_ci": true, "swedish_ci": true, "turkish_ci": true,
}

// DTPMode controls the DATETIME_PRECISION shim.
type DTPMode int

const (
	// DTPAuto rewrites only when the backend's version predates the column.
	// This is the default: on the servers this proxy exists for the shim is
	// needed, and on newer ones it would report a precision of 0 for columns
	// that actually have fractional seconds.
	DTPAuto DTPMode = iota
	// DTPAlways rewrites regardless of the backend version.
	DTPAlways
	// DTPNever leaves the statement alone.
	DTPNever
)

// ParseDTPMode reads the -rewrite-datetime-precision flag. "true" and "false"
// are accepted so that the boolean form this flag originally took keeps
// working.
func ParseDTPMode(s string) (DTPMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return DTPAuto, nil
	case "true", "on", "always":
		return DTPAlways, nil
	case "false", "off", "never":
		return DTPNever, nil
	}
	return DTPAuto, fmt.Errorf("unknown mode %q: want auto, always or never", s)
}

func (m DTPMode) String() string {
	switch m {
	case DTPAlways:
		return "always"
	case DTPNever:
		return "never"
	}
	return "auto"
}

// BackendHasDatetimePrecision reports whether a server calling itself version
// has information_schema.COLUMNS.DATETIME_PRECISION, and whether the version
// string was understood at all.
//
// The column arrived in MySQL 5.6 and, with the rest of fractional-second
// support, in MariaDB 5.3. MariaDB also reports itself two ways: plainly, as
// "10.11.2-MariaDB", and behind the compatibility prefix "5.5.5-" that exists
// so clients too old to parse a 10.x version still see something they accept —
// which would otherwise read as 5.5 and be badly wrong.
//
// An unrecognised version is reported as having the column. That direction
// fails loudly: the metadata query comes back "Unknown column
// 'DATETIME_PRECISION'", which is visible and fixable with -rewrite-datetime-
// precision=always. Guessing the other way would silently report every
// temporal column as having no fractional seconds.
func BackendHasDatetimePrecision(version string) (has, recognised bool) {
	v := strings.TrimPrefix(version, "5.5.5-") // MariaDB's compatibility prefix
	major, minor, ok := majorMinor(v)
	if !ok {
		return true, false
	}
	if strings.Contains(asciiFold(v), "mariadb") {
		return major > 5 || (major == 5 && minor >= 3), true
	}
	return major > 5 || (major == 5 && minor >= 6), true
}

// majorMinor reads the leading "<major>.<minor>" of a version string, ignoring
// whatever follows: a patch level, a "-log" suffix, a vendor name.
func majorMinor(v string) (major, minor int, ok bool) {
	read := func(s string) (int, string, bool) {
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 || i > 4 {
			return 0, s, false
		}
		n := 0
		for _, c := range []byte(s[:i]) {
			n = n*10 + int(c-'0')
		}
		return n, s[i:], true
	}
	major, rest, ok := read(v)
	if !ok || rest == "" || rest[0] != '.' {
		return 0, 0, false
	}
	minor, _, ok = read(rest[1:])
	if !ok {
		return 0, 0, false
	}
	return major, minor, true
}

// RewriteDatetimePrecision replaces the DATETIME_PRECISION column with the
// literal 0 in information_schema queries. That column arrived in MySQL 5.6, so
// on 5.0 and 5.1 every driver that reads column metadata fails outright:
//
//	Unknown column 'DATETIME_PRECISION' in 'field list'
//
// MariaDB Connector/J 3.x uses it in DatabaseMetaData.getColumns() (and three
// other metadata methods) to size temporal columns:
//
//	IF(DATETIME_PRECISION = 0, 19, CAST(20 + DATETIME_PRECISION as signed integer))
//
// so the substitution has to be 0, not NULL. Zero is also the truthful answer —
// a server without fractional seconds has precision 0 — and it keeps the
// arithmetic intact: NULL would poison the comparison and the CAST, and every
// temporal column would come back with a NULL size.
//
// Two things keep this narrow. It only fires on statements that mention
// information_schema, so an application column of the same name is untouched;
// and the match respects identifier boundaries, so MY_DATETIME_PRECISION and a
// backtick-quoted `DATETIME_PRECISION` are both left alone.
func RewriteDatetimePrecision(q string) string {
	const needle = "datetime_precision"
	lower := asciiFold(q)
	if !strings.Contains(lower, "information_schema") || !strings.Contains(lower, needle) {
		return q
	}
	var b strings.Builder
	b.Grow(len(q))
	for i := 0; i < len(q); {
		if strings.HasPrefix(lower[i:], needle) &&
			(i == 0 || !isIdentByte(q[i-1])) &&
			(i+len(needle) == len(q) || !isIdentByte(q[i+len(needle)])) {
			b.WriteByte('0')
			i += len(needle)
			continue
		}
		b.WriteByte(q[i])
		i++
	}
	return b.String()
}

// isIdentByte reports whether b can appear inside a MySQL identifier. The
// backtick counts: it means the identifier was quoted, and a quoted
// `DATETIME_PRECISION` must not become `0`, which would name a column "0".
func isIdentByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_', b == '$', b == '`':
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
