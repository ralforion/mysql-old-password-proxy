package unit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ralforion/mysql-old-password-proxy/internal/mysqlwire"
)

// fakeBackend is a MySQL 5.0-shaped server: it greets with the short handshake
// such a server sends (no plugin name, no upper capability word) and demands
// pre-4.1 authentication.
//
// It exists because the servers that need it are typically MySQL 4.1 to 5.1, which no current
// Docker image reproduces: 5.6 (the newest image that still speaks
// mysql_old_password) asks for the old scramble with a full AuthSwitchRequest,
// whereas 5.0 sends a bare 0xFE. Both styles are covered here; the integration
// suite then checks the whole thing against a real server.
type fakeBackend struct {
	ln   net.Listener
	user string
	pass string

	// switchStyle selects how the server asks for pre-4.1 authentication.
	switchStyle switchStyle

	mu       sync.Mutex
	caps     uint32
	sessions []*fakeSession
	closed   bool
}

// Caps returns the capabilities the backend currently advertises.
func (b *fakeBackend) Caps() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.caps
}

// SetCaps changes what the backend advertises from the next connection on, so
// tests can reproduce a server restarted onto a different version.
func (b *fakeBackend) SetCaps(c uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.caps = c
}

type switchStyle int

const (
	// switchBare is MySQL 5.0: a bare 0xFE meaning "old password, reuse the
	// scramble you already have".
	switchBare switchStyle = iota
	// switchRequest is MySQL 5.5 and later: a full AuthSwitchRequest naming
	// mysql_old_password and carrying a fresh scramble.
	switchRequest
	// switchNone accepts mysql_native_password without asking for anything.
	switchNone
)

// fakeSession records what one backend connection was asked to do. The
// handshake fields are written before the session is published; queries and
// quit are written while the test reads them, so they go through the mutex.
type fakeSession struct {
	user    string
	db      string
	charset byte
	caps    uint32

	mu      sync.Mutex
	queries []string
	quit    bool
}

// Queries returns the statements this session forwarded to the backend.
func (s *fakeSession) Queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// Quit reports whether the session ended with COM_QUIT.
func (s *fakeSession) Quit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.quit
}

// caps50 is the capability set a MySQL 5.0 server advertises: the low word
// only, with no CLIENT_PLUGIN_AUTH and nothing above bit 15.
const caps50 = mysqlwire.CapLongPassword | mysqlwire.CapFoundRows | mysqlwire.CapLongFlag |
	mysqlwire.CapConnectWithDB | mysqlwire.CapNoSchema | mysqlwire.CapCompress |
	mysqlwire.CapLocalFiles | mysqlwire.CapIgnoreSpace | mysqlwire.CapProtocol41 |
	mysqlwire.CapInteractive | mysqlwire.CapTransactions | mysqlwire.CapSecureConnection

func newFakeBackend(t *testing.T, style switchStyle, caps uint32, user, pass string) *fakeBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{ln: ln, caps: caps, user: user, pass: pass, switchStyle: style}
	go b.serve(t)
	t.Cleanup(b.Close)
	return b
}

func (b *fakeBackend) Addr() string { return b.ln.Addr().String() }

func (b *fakeBackend) Close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.ln.Close()
}

func (b *fakeBackend) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Sessions returns the backend connections seen so far.
func (b *fakeBackend) Sessions() []*fakeSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*fakeSession(nil), b.sessions...)
}

// LastSession returns the most recent backend connection, failing the test if
// there is none.
func (b *fakeBackend) LastSession(t *testing.T) *fakeSession {
	t.Helper()
	s := b.Sessions()
	if len(s) == 0 {
		t.Fatal("the relay never connected to the backend")
	}
	return s[len(s)-1]
}

func (b *fakeBackend) serve(t *testing.T) {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			if err := b.handle(c); err != nil && !errors.Is(err, errClientGone) && !b.isClosed() {
				t.Logf("fake backend: %v", err)
			}
		}()
	}
}

var errClientGone = errors.New("client disconnected")

func (b *fakeBackend) handle(c net.Conn) error {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(c)

	caps := b.Caps()
	scramble := []byte("ABCDEFGHIJKLMNOPQRST")
	if err := mysqlwire.WritePacket(c, b.greeting(caps, scramble), 0); err != nil {
		return err
	}

	payload, _, err := mysqlwire.ReadPacket(r)
	if err != nil {
		return errClientGone
	}
	hr, err := mysqlwire.ParseHandshakeResponse41(payload)
	if err != nil {
		return err
	}
	sess := &fakeSession{user: hr.User, db: hr.DB, charset: hr.Charset, caps: hr.Caps}
	b.mu.Lock()
	b.sessions = append(b.sessions, sess)
	b.mu.Unlock()

	// A server that advertises CLIENT_PLUGIN_AUTH requires the client to claim
	// it and to name a plugin. MySQL 5.6 answers "Bad handshake" otherwise,
	// even for an account whose password predates plugins entirely.
	if caps&mysqlwire.CapPluginAuth != 0 {
		if hr.Caps&mysqlwire.CapPluginAuth == 0 || hr.Plugin == "" {
			return mysqlwire.WritePacket(c, mysqlwire.ErrPacket(1043, "08S01", "Bad handshake"), 2)
		}
	}

	// The relay must never offer the backend a capability the backend lacks.
	if extra := hr.Caps &^ caps; extra&^(mysqlwire.CapProtocol41|mysqlwire.CapSecureConnection|mysqlwire.CapPluginAuth) != 0 {
		return fmt.Errorf("the relay negotiated capabilities the server never offered: 0x%08x", extra)
	}

	authResp := hr.AuthResp
	switch b.switchStyle {
	case switchBare:
		if err := mysqlwire.WritePacket(c, []byte{0xFE}, 2); err != nil {
			return err
		}
		if authResp, _, err = mysqlwire.ReadPacket(r); err != nil {
			return err
		}
		err = b.checkOldPassword(authResp, scramble)
	case switchRequest:
		fresh := []byte("0123456789abcdefghij")
		if err := mysqlwire.WritePacket(c, mysqlwire.AuthSwitchRequest(mysqlwire.OldPasswordPlugin, fresh), 2); err != nil {
			return err
		}
		if authResp, _, err = mysqlwire.ReadPacket(r); err != nil {
			return err
		}
		err = b.checkOldPassword(authResp, fresh)
	case switchNone:
		if !bytes.Equal(authResp, mysqlwire.NativePassword(scramble, b.pass)) {
			err = errors.New("bad native password")
		}
	}
	if err == nil && hr.User != b.user {
		err = fmt.Errorf("unknown user %q", hr.User)
	}
	if err != nil {
		return mysqlwire.WritePacket(c, mysqlwire.ErrPacket(1045, "28000",
			fmt.Sprintf("Access denied for user '%s'@'relay' (%v)", hr.User, err)), 4)
	}
	if err := mysqlwire.WritePacket(c, mysqlwire.OKPacket(), 4); err != nil {
		return err
	}

	return b.commandLoop(c, r, sess)
}

// checkOldPassword verifies the pre-4.1 response: eight scrambled bytes and a
// NUL terminator.
func (b *fakeBackend) checkOldPassword(got, scramble []byte) error {
	want := append(mysqlwire.ScrambleOldPassword(scramble, b.pass), 0x00)
	if !bytes.Equal(got, want) {
		return fmt.Errorf("bad pre-4.1 auth response %x, want %x", got, want)
	}
	return nil
}

// greeting builds the Initial Handshake Packet in the shape MySQL 5.0 sends:
// the capability low word, then thirteen zero filler bytes, then the rest of
// the scramble — and no authentication plugin name.
func (b *fakeBackend) greeting(caps uint32, scramble []byte) []byte {
	p := []byte{10}
	p = append(p, "5.0.96-fake\x00"...)
	p = append(p, 7, 0, 0, 0) // connection id
	p = append(p, scramble[:8]...)
	p = append(p, 0)                         // filler
	p = append(p, byte(caps), byte(caps>>8)) // capability flags, low word
	p = append(p, 8)                         // latin1_swedish_ci
	p = append(p, 0x02, 0x00)                // status flags
	p = append(p, byte(caps>>16), byte(caps>>24))
	p = append(p, make([]byte, 11)...) // auth-plugin-data length + reserved
	p = append(p, scramble[8:]...)
	return append(p, 0)
}

// commandLoop answers COM_QUERY with a one-row result set framed the way a
// server without CLIENT_DEPRECATE_EOF frames it, and records what it was asked.
func (b *fakeBackend) commandLoop(c net.Conn, r *bufio.Reader, sess *fakeSession) error {
	for {
		c.SetDeadline(time.Now().Add(30 * time.Second))
		payload, _, err := mysqlwire.ReadPacket(r)
		if err != nil {
			return errClientGone
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case mysqlwire.ComQuit:
			sess.mu.Lock()
			sess.quit = true
			sess.mu.Unlock()
			return nil
		case mysqlwire.ComQuery:
			q := string(payload[1:])
			sess.mu.Lock()
			sess.queries = append(sess.queries, q)
			sess.mu.Unlock()
			if err := writeResultSet(c, "result", q); err != nil {
				return err
			}
		default:
			if err := mysqlwire.WritePacket(c, mysqlwire.ErrPacket(1047, "08S01",
				fmt.Sprintf("unsupported command 0x%02x", payload[0])), 1); err != nil {
				return err
			}
		}
	}
}

// writeResultSet emits column count, one column definition, EOF, one row, EOF.
func writeResultSet(w net.Conn, column, value string) error {
	if err := mysqlwire.WritePacket(w, []byte{0x01}, 1); err != nil { // one column
		return err
	}
	if err := mysqlwire.WritePacket(w, columnDefinition(column), 2); err != nil {
		return err
	}
	if err := mysqlwire.WritePacket(w, eofPacket(), 3); err != nil {
		return err
	}
	row := lenencString(value)
	if err := mysqlwire.WritePacket(w, row, 4); err != nil {
		return err
	}
	return mysqlwire.WritePacket(w, eofPacket(), 5)
}

func columnDefinition(name string) []byte {
	p := lenencString("def") // catalog
	p = append(p, lenencString("")...)
	p = append(p, lenencString("")...)
	p = append(p, lenencString("")...)
	p = append(p, lenencString(name)...) // name
	p = append(p, lenencString(name)...) // original name
	p = append(p, 0x0C)                  // length of the fixed-length fields
	p = append(p, 33, 0)                 // character set: utf8_general_ci
	p = append(p, 0xFF, 0xFF, 0, 0)      // column length
	p = append(p, 0xFD)                  // MYSQL_TYPE_VAR_STRING
	p = append(p, 0, 0)                  // flags
	p = append(p, 0)                     // decimals
	return append(p, 0, 0)               // filler
}

func lenencString(s string) []byte {
	return append([]byte{byte(len(s))}, s...)
}

func eofPacket() []byte { return []byte{0xFE, 0x00, 0x00, 0x02, 0x00} }
