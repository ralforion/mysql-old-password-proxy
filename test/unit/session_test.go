package unit

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ralforion/mysql-old-password-proxy/internal/mysqlwire"
	"github.com/ralforion/mysql-old-password-proxy/internal/relay"
)

// These tests run a real relay.Server in-process against the MySQL 5.0-shaped
// fake backend, so the full connection phase — including the pre-4.1 fallback
// the production server uses — is covered without Docker.

const (
	legacyUser = "legacyacct"
	legacyPass = "legacypw"
	frontUser  = "appuser"
	frontPass  = "frontendpw"
)

// startRelay wires a relay to a fake backend and returns its address.
func startRelay(t *testing.T, backend *fakeBackend, tweak func(*relay.Config)) (string, *relay.Server) {
	t.Helper()
	var logs lockedBuffer
	cfg := relay.Config{
		Backend:        backend.Addr(),
		BackendUser:    legacyUser,
		BackendPass:    legacyPass,
		FrontendUser:   frontUser,
		FrontendPass:   frontPass,
		ServerVersion:  "5.5.62-auth-relay",
		RewriteUTF8MB4: true,
		DialTimeout:    5 * time.Second,
		AuthTimeout:    10 * time.Second,
		Logger:         log.New(&logs, "relay: ", 0),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	srv, err := relay.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ln.Close()
		if t.Failed() {
			t.Logf("relay log:\n%s", logs.String())
		}
	})
	return ln.Addr().String(), srv
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// client is a minimal MySQL client used to drive the relay.
type client struct {
	conn net.Conn
	r    *bufio.Reader
	caps uint32
}

type loginOpts struct {
	user, pass string
	db         string
	extraCaps  uint32
	plugin     string // sent as the client's chosen auth plugin
	// capsOverride replaces the capabilities the client would otherwise accept
	// from the relay's offer, for testing what a frugal client gets.
	capsOverride uint32
}

// dial performs the client half of the connection phase and returns the
// relay's final packet, which is an OK or an ERR.
func dial(t *testing.T, addr string, o loginOpts) (*client, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	c := &client{conn: conn, r: bufio.NewReader(conn)}
	greeting, _, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	serverCaps, scramble, err := mysqlwire.ParseServerHandshake(greeting)
	if err != nil {
		t.Fatalf("parse greeting: %v", err)
	}
	if serverCaps&mysqlwire.CapDeprecateEOF != 0 {
		t.Fatal("the relay offered CLIENT_DEPRECATE_EOF, which it must never do")
	}
	if serverCaps&mysqlwire.CapSSL != 0 {
		t.Fatal("the relay offered CLIENT_SSL, which it does not implement")
	}
	if !bytes.Contains(greeting, []byte(mysqlwire.NativePasswordPlugin)) {
		t.Fatal("the relay did not advertise mysql_native_password")
	}

	c.caps = (serverCaps & relay.FramingSafe) | mysqlwire.CapProtocol41 |
		mysqlwire.CapSecureConnection | o.extraCaps
	if o.capsOverride != 0 {
		c.caps = o.capsOverride
	}
	if o.db == "" {
		c.caps &^= mysqlwire.CapConnectWithDB
	}
	plugin := o.plugin
	if plugin != "" {
		c.caps |= mysqlwire.CapPluginAuth
	}

	resp := mysqlwire.BuildHandshakeResponse41(c.caps, 45, o.user,
		mysqlwire.NativePassword(scramble, o.pass), o.db, "")
	if plugin != "" {
		resp = append(resp, plugin...)
		resp = append(resp, 0)
	}
	if err := mysqlwire.WritePacket(conn, resp, 1); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}

	p, seq, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	// An auth-switch request means the relay wants mysql_native_password.
	if mysqlwire.IsAuthSwitch(p) && len(p) > 1 {
		name, newScramble := mysqlwire.ParseAuthSwitch(p)
		if name != mysqlwire.NativePasswordPlugin {
			t.Fatalf("the relay asked for plugin %q, want mysql_native_password", name)
		}
		if err := mysqlwire.WritePacket(conn, mysqlwire.NativePassword(newScramble, o.pass), seq+1); err != nil {
			t.Fatalf("write auth switch response: %v", err)
		}
		if p, _, err = mysqlwire.ReadPacket(c.r); err != nil {
			t.Fatalf("read auth switch result: %v", err)
		}
	}
	return c, p
}

func mustDial(t *testing.T, addr string, o loginOpts) *client {
	t.Helper()
	c, p := dial(t, addr, o)
	if !mysqlwire.IsOK(p) {
		t.Fatalf("login failed: %s", mysqlwire.ErrText(p))
	}
	return c
}

// query sends a COM_QUERY and reads the response, returning the single value
// the fake backend echoes back.
func (c *client) query(t *testing.T, sql string) string {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, append([]byte{mysqlwire.ComQuery}, sql...), 0); err != nil {
		t.Fatalf("write query: %v", err)
	}
	first, _, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	switch {
	case mysqlwire.IsOK(first):
		return ""
	case mysqlwire.IsErr(first):
		t.Fatalf("query error: %s", mysqlwire.ErrText(first))
	}
	n, adv := mysqlwire.LenencInt(first)
	if adv == 0 || n != 1 {
		t.Fatalf("column count packet = %x", first)
	}
	if _, _, err := mysqlwire.ReadPacket(c.r); err != nil { // column definition
		t.Fatalf("read column definition: %v", err)
	}
	if p, _, err := mysqlwire.ReadPacket(c.r); err != nil {
		t.Fatalf("read column EOF: %v", err)
	} else if !mysqlwire.IsEOF(p) {
		t.Fatalf("expected EOF after the column definitions, got %x — framing is out of step", p)
	}
	row, _, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	if p, _, err := mysqlwire.ReadPacket(c.r); err != nil {
		t.Fatalf("read row EOF: %v", err)
	} else if !mysqlwire.IsEOF(p) {
		t.Fatalf("expected EOF after the rows, got %x", p)
	}
	if len(row) < 1 {
		t.Fatal("empty row packet")
	}
	return string(row[1:])
}

// isOKResponse reads a bare OK, as produced by an intercepted statement.
func (c *client) sendQueryExpectOK(t *testing.T, sql string) {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, append([]byte{mysqlwire.ComQuery}, sql...), 0); err != nil {
		t.Fatalf("write query: %v", err)
	}
	p, seq, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !mysqlwire.IsOK(p) {
		t.Fatalf("want an OK packet, got %x", p)
	}
	if seq != 1 {
		t.Errorf("OK sequence id = %d, want 1", seq)
	}
}

// ------------------------------------------------------------------- tests ---

// TestLoginAgainstMySQL50Style is the central case: the backend answers the
// 4.1 handshake with a bare 0xFE, exactly as MySQL 5.0 does, and the relay
// completes the pre-4.1 exchange on the client's behalf.
func TestLoginAgainstMySQL50Style(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})
	if got := c.query(t, "SELECT 1"); got != "SELECT 1" {
		t.Errorf("the backend saw %q", got)
	}

	sess := be.LastSession(t)
	if sess.user != legacyUser {
		t.Errorf("the relay authenticated as %q, want the legacy account %q", sess.user, legacyUser)
	}
	// The client's requested schema must reach the backend handshake, not be
	// dropped or replayed later.
	if sess.db != "legacydb" {
		t.Errorf("backend schema = %q, want legacydb", sess.db)
	}
	// A 5.0 server rejects utf8mb4 collation ids outright.
	if sess.charset != 33 {
		t.Errorf("backend charset = %d, want 33 (the client asked for utf8mb4, id 45)", sess.charset)
	}
	if sess.caps&mysqlwire.CapDeprecateEOF != 0 || sess.caps&mysqlwire.CapCompress != 0 {
		t.Errorf("the relay negotiated unsafe capabilities with the backend: 0x%08x", sess.caps)
	}
}

// TestLoginAgainstAuthSwitchStyle covers the MySQL 5.5+ spelling of the same
// exchange: a full AuthSwitchRequest with a fresh scramble.
func TestLoginAgainstAuthSwitchStyle(t *testing.T) {
	be := newFakeBackend(t, switchRequest, caps56, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})
	if got := c.query(t, "SELECT 1"); got != "SELECT 1" {
		t.Errorf("the backend saw %q", got)
	}
}

// TestLoginAgainstNativeOnlyBackend checks the relay still works against a
// backend that never asks to switch — the case where the DBA finally does run
// ALTER USER and the relay is left in place.
func TestLoginAgainstNativeOnlyBackend(t *testing.T) {
	be := newFakeBackend(t, switchNone, caps56, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass})
	if got := c.query(t, "SELECT 1"); got != "SELECT 1" {
		t.Errorf("the backend saw %q", got)
	}
	if db := be.LastSession(t).db; db != "" {
		t.Errorf("backend schema = %q, want empty", db)
	}
}

// TestNoSchemaMeansNoConnectWithDB checks the relay does not claim
// CLIENT_CONNECT_WITH_DB when it has no schema to send.
func TestNoSchemaMeansNoConnectWithDB(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass})
	if caps := be.LastSession(t).caps; caps&mysqlwire.CapConnectWithDB != 0 {
		t.Errorf("backend capabilities 0x%08x include CLIENT_CONNECT_WITH_DB with no schema to send", caps)
	}
}

// TestCredentialsAreSeparate checks the two credential sets are independent:
// the frontend password opens the relay, the legacy one does not.
func TestCredentialsAreSeparate(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	// One good login first, so the capability cache is primed and any later
	// backend connection can only have come from a login that should not have
	// been accepted.
	mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})
	before := len(be.Sessions())

	for _, tc := range []struct{ name, user, pass string }{
		{"wrong password", frontUser, "not-the-password"},
		{"unknown user", "someone-else", frontPass},
		{"the legacy credentials", legacyUser, legacyPass},
		{"empty password", frontUser, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, p := dial(t, addr, loginOpts{user: tc.user, pass: tc.pass, db: "legacydb"})
			if !mysqlwire.IsErr(p) {
				t.Fatalf("the relay accepted %s", tc.name)
			}
			if code := mysqlwire.ErrCode(p); code != 1045 {
				t.Errorf("error code = %d, want 1045", code)
			}
			if !strings.Contains(mysqlwire.ErrText(p), "Access denied") {
				t.Errorf("error text = %q", mysqlwire.ErrText(p))
			}
		})
	}
	// A rejected login must never have reached the legacy server.
	if n := len(be.Sessions()) - before; n != 0 {
		t.Errorf("the backend saw %d connections for logins that should have been refused", n)
	}
}

// TestAuthPluginSwitch covers a client that offers another plugin first, as a
// MySQL 8 client does with caching_sha2_password.
func TestAuthPluginSwitch(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	c := mustDial(t, addr, loginOpts{
		user: frontUser, pass: frontPass, db: "legacydb", plugin: "caching_sha2_password",
	})
	if got := c.query(t, "SELECT 1"); got != "SELECT 1" {
		t.Errorf("the backend saw %q", got)
	}
}

// TestDangerousCapabilityIsIgnored covers what a real MySQL server does with
// capabilities it never advertised: ignore them, so that the set in force is
// the intersection. Stock clients send CLIENT_DEPRECATE_EOF and friends
// unconditionally — refusing them would lock out every modern client — and what
// must hold is that the relayed framing stays the one the relay offered.
func TestDangerousCapabilityIsIgnored(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	for name, bit := range map[string]uint32{
		"CLIENT_DEPRECATE_EOF":    mysqlwire.CapDeprecateEOF,
		"CLIENT_SESSION_TRACK":    mysqlwire.CapSessionTrack,
		"CLIENT_COMPRESS":         mysqlwire.CapCompress,
		"CLIENT_QUERY_ATTRIBUTES": mysqlwire.CapQueryAttributes,
		"everything at once":      0xFFFFFFFF &^ mysqlwire.CapSSL,
	} {
		t.Run(name, func(t *testing.T) {
			c, p := dial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb", extraCaps: bit})
			if !mysqlwire.IsOK(p) {
				t.Fatalf("the relay refused a client claiming %s: %s", name, mysqlwire.ErrText(p))
			}
			// query insists on EOF-terminated framing on every response.
			if got := c.query(t, "SELECT 1"); got != "SELECT 1" {
				t.Errorf("the backend saw %q", got)
			}
			// And the backend must never have been told about the extra bit.
			if used := be.LastSession(t).caps & bit &^ (relay.FramingSafe); used != 0 {
				t.Errorf("the relay passed 0x%08x on to the backend", used)
			}
		})
	}
}

// TestStaleCapabilityCacheIsRefused covers the one case CheckCapabilities
// exists for: the backend is restarted onto a version with fewer capabilities
// than the offer the client accepted was built from. Relaying then would frame
// result sets one way on one side and the other way on the other, so the
// connection is refused instead.
func TestStaleCapabilityCacheIsRefused(t *testing.T) {
	be := newFakeBackend(t, switchRequest, caps56, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	// Prime the cache while the backend still advertises the full set.
	mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})

	// The backend comes back without CLIENT_MULTI_RESULTS, so it can no longer
	// frame the multiple result sets the client was told to expect.
	be.SetCaps(caps56 &^ mysqlwire.CapMultiResults)

	_, p := dial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})
	if !mysqlwire.IsErr(p) {
		t.Fatalf("the relay relayed across a capability change: %x", p)
	}
	if !strings.Contains(mysqlwire.ErrText(p), "capability mismatch") {
		t.Errorf("error text = %q, want it to name the capability mismatch", mysqlwire.ErrText(p))
	}
}

// TestUTF8MB4Rewrite checks what actually reaches the legacy server.
func TestUTF8MB4Rewrite(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)
	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})

	c.query(t, "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci")
	c.query(t, "SELECT 'Grüße', '日本語'")

	got := be.LastSession(t).Queries()
	want := []string{"SET NAMES utf8 COLLATE utf8_unicode_ci", "SELECT 'Grüße', '日本語'"}
	if len(got) != len(want) {
		t.Fatalf("the backend saw %d queries, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("query %d: backend saw %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUTF8MB4RewriteCanBeDisabled(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, func(c *relay.Config) { c.RewriteUTF8MB4 = false })
	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})

	c.query(t, "SET NAMES utf8mb4")
	if got := be.LastSession(t).Queries(); len(got) != 1 || got[0] != "SET NAMES utf8mb4" {
		t.Errorf("the backend saw %q, want the statement unchanged", got)
	}
	// The charset in the handshake must be passed through untouched too.
	if cs := be.LastSession(t).charset; cs != 45 {
		t.Errorf("backend charset = %d, want the client's 45", cs)
	}
}

// TestFakeOKInterceptsStatements covers the escape hatch for session setup a
// MySQL 5.0 server rejects: matching statements are answered without being
// forwarded.
func TestFakeOKInterceptsStatements(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, func(c *relay.Config) {
		c.FakeOK = regexp.MustCompile(`(?i)^SET\s+(session_track|@@session\.session_track)`)
	})
	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})

	c.sendQueryExpectOK(t, "SET session_track_schema=1")
	// The session must carry on normally afterwards.
	if got := c.query(t, "SELECT 1"); got != "SELECT 1" {
		t.Errorf("the backend saw %q", got)
	}
	if got := be.LastSession(t).Queries(); len(got) != 1 || got[0] != "SELECT 1" {
		t.Errorf("the backend saw %q, want only the statement that was not intercepted", got)
	}
}

// TestSplitPacketPassesThrough sends a statement larger than 16 MB. The
// protocol carries it as a full 0xFFFFFF packet plus a continuation, and the
// continuation must not be mistaken for a new command or rewritten.
func TestSplitPacketPassesThrough(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)
	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})

	// The continuation deliberately starts with the COM_QUERY byte and carries
	// the utf8mb4 literal, so a relay that misread it would be caught here.
	head := "SELECT '" + strings.Repeat("a", mysqlwire.MaxPayload-10)
	tail := "\x03 utf8mb4 tail'"
	sql := head + tail
	payload := append([]byte{mysqlwire.ComQuery}, sql...)

	seq := byte(0)
	for len(payload) >= mysqlwire.MaxPayload {
		if err := mysqlwire.WritePacket(c.conn, payload[:mysqlwire.MaxPayload], seq); err != nil {
			t.Fatalf("write chunk: %v", err)
		}
		payload = payload[mysqlwire.MaxPayload:]
		seq++
	}
	if err := mysqlwire.WritePacket(c.conn, payload, seq); err != nil {
		t.Fatalf("write final chunk: %v", err)
	}
	if seq == 0 {
		t.Fatal("the statement did not actually split")
	}

	// The fake backend reassembles nothing, so it records the first chunk; what
	// matters is that both chunks arrived unaltered and in order.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(be.LastSession(t).Queries()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := be.LastSession(t).Queries()
	if len(got) == 0 {
		t.Fatal("the backend never saw the split statement")
	}
	if !strings.HasPrefix(got[0], "SELECT '"+strings.Repeat("a", 100)) {
		t.Errorf("the first chunk was altered: %.60q", got[0])
	}
	if len(got[0]) != mysqlwire.MaxPayload-1 {
		t.Errorf("the first chunk is %d bytes, want %d", len(got[0]), mysqlwire.MaxPayload-1)
	}
}

// TestQuitIsForwarded checks COM_QUIT reaches the legacy server, so it closes
// the session cleanly instead of counting an aborted connection.
func TestQuitIsForwarded(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)
	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})

	if err := mysqlwire.WritePacket(c.conn, []byte{mysqlwire.ComQuit}, 0); err != nil {
		t.Fatal(err)
	}
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := mysqlwire.ReadPacket(c.r); err == nil {
		t.Error("the relay kept the connection open after COM_QUIT")
	} else if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Logf("close reported as %v (acceptable)", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if be.LastSession(t).Quit() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("COM_QUIT never reached the backend")
}

// TestBackendDownIsReported covers the failure mode from the test plan: with
// the legacy server unreachable the client must get an error, not a hang.
func TestBackendDownIsReported(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	// One successful session first, so the capability cache is primed and the
	// relay takes its ordinary path.
	mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})
	be.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, p := dial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})
		if !mysqlwire.IsErr(p) {
			t.Errorf("with the backend down the relay answered %x, want an error packet", p)
			return
		}
		if !strings.Contains(mysqlwire.ErrText(p), "could not reach the legacy server") {
			t.Errorf("error text = %q", mysqlwire.ErrText(p))
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the relay hung instead of reporting that the backend is down")
	}
}

// TestBackendDownBeforeAnyProbe covers the same failure at boot, when the
// relay has not yet learned the backend's capabilities.
func TestBackendDownBeforeAnyProbe(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	backendAddr := be.Addr()
	be.Close()

	srv, err := relay.New(relay.Config{
		Backend: backendAddr, BackendUser: legacyUser, BackendPass: legacyPass,
		FrontendUser: frontUser, FrontendPass: frontPass,
		DialTimeout: 2 * time.Second, AuthTimeout: 2 * time.Second,
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	// With no capabilities learned there is nothing to greet with, so the relay
	// must send an error packet in place of the initial handshake.
	p, _, err := mysqlwire.ReadPacket(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !mysqlwire.IsErr(p) {
		t.Fatalf("want an error packet in place of the greeting, got %x", p)
	}
	if !strings.Contains(mysqlwire.ErrText(p), "could not reach the legacy server") {
		t.Errorf("error text = %q", mysqlwire.ErrText(p))
	}
}

// TestProbeBackendValidatesCredentials checks the startup probe catches a bad
// secret at boot rather than on the first query.
func TestProbeBackendValidatesCredentials(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)

	good, err := relay.New(relay.Config{
		Backend: be.Addr(), BackendUser: legacyUser, BackendPass: legacyPass,
		FrontendPass: frontPass, Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	caps, err := good.ProbeBackend()
	if err != nil {
		t.Fatalf("probe with correct credentials: %v", err)
	}
	if caps != caps50 {
		t.Errorf("probe learned capabilities 0x%08x, want 0x%08x", caps, uint32(caps50))
	}
	if got, known := good.BackendCaps(); !known || got != caps50 {
		t.Errorf("the probe did not prime the capability cache: 0x%08x known=%v", got, known)
	}
	// The probe must disconnect politely, so the server does not count an
	// aborted connection against its host cache.
	if !waitFor(5*time.Second, func() bool { return be.LastSession(t).Quit() }) {
		t.Error("the probe did not close its backend session with COM_QUIT")
	}

	bad, err := relay.New(relay.Config{
		Backend: be.Addr(), BackendUser: legacyUser, BackendPass: "wrong",
		FrontendPass: frontPass, Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.ProbeBackend(); err == nil {
		t.Error("the probe accepted a wrong backend password")
	} else if !strings.Contains(err.Error(), "rejected login") {
		t.Errorf("error = %v, want it to report the rejected login", err)
	}
}

// TestConcurrentSessionsAreIndependent catches state accidentally shared
// between connections.
func TestConcurrentSessionsAreIndependent(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := "schema" + string(rune('a'+i))
			c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: db})
			for n := 0; n < 5; n++ {
				sql := "SELECT " + db
				if got := c.query(t, sql); got != sql {
					t.Errorf("session %d saw %q, want %q", i, got, sql)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	// Every session must have carried its own schema through to the backend.
	// Sessions with no schema are capability probes, not client sessions.
	seen := map[string]bool{}
	for _, s := range be.Sessions() {
		if s.db == "" {
			continue
		}
		if seen[s.db] {
			t.Errorf("two backend sessions claimed the schema %q", s.db)
		}
		seen[s.db] = true
	}
	if len(seen) != 12 {
		t.Errorf("the backend saw %d distinct client schemas, want 12", len(seen))
	}
}

// waitFor polls until cond holds or the timeout expires, for the handful of
// assertions about what the backend saw asynchronously.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// TestGracefulDrain checks Wait blocks while a session is live, which is what
// makes a rolling update safe.
func TestGracefulDrain(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	var logs lockedBuffer
	srv, err := relay.New(relay.Config{
		Backend: be.Addr(), BackendUser: legacyUser, BackendPass: legacyPass,
		FrontendUser: frontUser, FrontendPass: frontPass,
		Logger: log.New(&logs, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() { srv.Serve(ln); close(served) }()

	c := mustDial(t, ln.Addr().String(), loginOpts{user: frontUser, pass: frontPass})
	ln.Close()
	<-served // Serve returns as soon as the listener closes

	ctx, cancel := contextWithTimeout(300 * time.Millisecond)
	defer cancel()
	if srv.Wait(ctx) {
		t.Error("Wait returned while a session was still open")
	}

	c.conn.Close()
	ctx2, cancel2 := contextWithTimeout(10 * time.Second)
	defer cancel2()
	if !srv.Wait(ctx2) {
		t.Error("Wait did not return after the session closed")
	}
}

// TestMaxConnections covers the bound on how many connections the legacy server
// can be asked to hold. There is no pooling — one client session is one backend
// session — so this is what keeps a burst of clients from exhausting
// max_connections on a server that may have other users.
func TestMaxConnections(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, srv := startRelay(t, be, func(c *relay.Config) { c.MaxConnections = 2 })

	a := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "one"})
	b := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "two"})

	// Both sessions must still work: the limit bounds concurrency, it does not
	// serialise anything.
	if got := a.query(t, "SELECT a"); got != "SELECT a" {
		t.Errorf("first session: %q", got)
	}
	if got := b.query(t, "SELECT b"); got != "SELECT b" {
		t.Errorf("second session: %q", got)
	}
	if n := srv.LiveConnections(); n != 2 {
		t.Errorf("LiveConnections = %d, want 2", n)
	}

	// The third is refused with the error MySQL itself would send, before the
	// legacy server is ever contacted.
	sessionsBefore := len(be.Sessions())
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	p, _, err := mysqlwire.ReadPacket(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !mysqlwire.IsErr(p) {
		t.Fatalf("the relay accepted a connection over the limit: %x", p)
	}
	if code := mysqlwire.ErrCode(p); code != 1040 {
		t.Errorf("error code = %d, want 1040 (ER_CON_COUNT_ERROR)", code)
	}
	if n := len(be.Sessions()) - sessionsBefore; n != 0 {
		t.Errorf("a refused connection reached the backend %d times", n)
	}

	// Closing one frees a slot.
	a.conn.Close()
	if !waitFor(5*time.Second, func() bool { return srv.LiveConnections() == 1 }) {
		t.Fatalf("LiveConnections stayed at %d after a session closed", srv.LiveConnections())
	}
	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "three"})
	if got := c.query(t, "SELECT c"); got != "SELECT c" {
		t.Errorf("third session: %q", got)
	}
}

// TestReuseBackendPassword covers the single-credential deployment: clients
// authenticate with the legacy server's own password, which the relay still
// verifies itself. The two sides remain separate authentications — the client's
// response cannot be forwarded, because it is a one-way function of a scramble
// only the relay chose.
func TestReuseBackendPassword(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, func(c *relay.Config) {
		c.FrontendUser = legacyUser
		c.FrontendPass = legacyPass // what -frontend-password-from-backend arranges
	})

	c := mustDial(t, addr, loginOpts{user: legacyUser, pass: legacyPass, db: "legacydb"})
	if got := c.query(t, "SELECT 1"); got != "SELECT 1" {
		t.Errorf("the backend saw %q", got)
	}
	// Verification still happens: the same password, but still checked.
	if _, p := dial(t, addr, loginOpts{user: legacyUser, pass: "wrong", db: "legacydb"}); !mysqlwire.IsErr(p) {
		t.Error("the relay accepted a wrong password when reusing the backend one")
	}
}

// TestDatetimePrecisionShimIsGatedOnVersion checks the shim follows the
// backend's version rather than firing everywhere. The column arrived in MySQL
// 5.6, so a 5.0 server needs the substitution and a 5.6 one must be left alone
// — otherwise every temporal column with fractional seconds would report a
// precision of 0 on a server that knows better.
func TestDatetimePrecisionShimIsGatedOnVersion(t *testing.T) {
	const query = "SELECT IF(DATETIME_PRECISION = 0, 19, 20) FROM information_schema.COLUMNS"

	tests := []struct {
		name    string
		version string
		mode    relay.DTPMode
		want    string
	}{
		{"5.0 lacks the column", "5.0.96-fake", relay.DTPAuto,
			"SELECT IF(0 = 0, 19, 20) FROM information_schema.COLUMNS"},
		{"5.1 lacks the column", "5.1.73", relay.DTPAuto,
			"SELECT IF(0 = 0, 19, 20) FROM information_schema.COLUMNS"},
		{"5.5 lacks the column", "5.5.62-log", relay.DTPAuto,
			"SELECT IF(0 = 0, 19, 20) FROM information_schema.COLUMNS"},
		{"5.6 has it, leave it alone", "5.6.51", relay.DTPAuto, query},
		{"8.0 has it", "8.0.36", relay.DTPAuto, query},
		{"MariaDB behind its compatibility prefix has it", "5.5.5-10.11.2-MariaDB", relay.DTPAuto, query},
		{"an unreadable version is left alone, so the failure is loud", "wat", relay.DTPAuto, query},
		// The mode overrides the version either way.
		{"always, on a server that has the column", "8.0.36", relay.DTPAlways,
			"SELECT IF(0 = 0, 19, 20) FROM information_schema.COLUMNS"},
		{"never, on a server that lacks it", "5.0.96-fake", relay.DTPNever, query},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
			be.SetVersion(tc.version)
			addr, _ := startRelay(t, be, func(c *relay.Config) { c.RewriteDTP = tc.mode })

			c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})
			c.query(t, query)

			got := be.LastSession(t).Queries()
			if len(got) != 1 {
				t.Fatalf("the backend saw %d queries, want 1", len(got))
			}
			if got[0] != tc.want {
				t.Errorf("backend %q saw:\n %q\nwant:\n %q", tc.version, got[0], tc.want)
			}
		})
	}
}

// TestSchemaQualifiedNamesWork is a regression test for CLIENT_NO_SCHEMA. That
// capability changes no framing, so it sat in FramingSafe until a
// schema-qualified query was tried: it tells the server to reject
// database.table qualifiers, and every such query failed with the table
// resolved against the default schema instead.
func TestSchemaQualifiedNamesWork(t *testing.T) {
	be := newFakeBackend(t, switchBare, caps50, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)
	c := mustDial(t, addr, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})

	const q = "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'legacydb'"
	if got := c.query(t, q); got != q {
		t.Errorf("the backend saw %q", got)
	}
	if caps := be.LastSession(t).caps; caps&mysqlwire.CapNoSchema != 0 {
		t.Errorf("the relay negotiated CLIENT_NO_SCHEMA with the backend (caps 0x%08x), "+
			"which makes the server reject database.table qualifiers", caps)
	}
}

// TestBackendSessionMirrorsClientCapabilities checks the relay opens a backend
// session that behaves like the one the client thinks it has. A capability
// negotiated on one half only changes what statements mean across the relay —
// CLIENT_FOUND_ROWS would have an UPDATE report matched rows to one side and
// changed rows to the other.
func TestBackendSessionMirrorsClientCapabilities(t *testing.T) {
	be := newFakeBackend(t, switchRequest, caps56, legacyUser, legacyPass)
	addr, _ := startRelay(t, be, nil)

	// A client that wants nothing beyond the minimum.
	minimal := mysqlwire.CapProtocol41 | mysqlwire.CapSecureConnection
	c, p := dial(t, addr, loginOpts{user: frontUser, pass: frontPass, capsOverride: minimal})
	if !mysqlwire.IsOK(p) {
		t.Fatalf("login failed: %s", mysqlwire.ErrText(p))
	}
	c.query(t, "SELECT 1")

	got := be.LastSession(t).caps
	if extra := got & relay.FramingSafe &^ minimal; extra != 0 {
		t.Errorf("the relay negotiated 0x%08x with the backend that the client did not ask for", extra)
	}

	// And a client that takes everything on offer gets it end to end.
	be2 := newFakeBackend(t, switchRequest, caps56, legacyUser, legacyPass)
	addr2, _ := startRelay(t, be2, nil)
	c2 := mustDial(t, addr2, loginOpts{user: frontUser, pass: frontPass, db: "legacydb"})
	c2.query(t, "SELECT 1")

	client2 := be2.LastSession(t).caps
	if client2&mysqlwire.CapFoundRows == 0 {
		t.Errorf("the backend session lost CLIENT_FOUND_ROWS the client negotiated (caps 0x%08x)", client2)
	}
}
