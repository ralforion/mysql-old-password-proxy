package unit

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ralforion/mysql-old-password-proxy/internal/mysqlwire"
)

// realHandshake56 is the Initial Handshake Packet captured from mysql:5.6.51,
// the newest server that still implements mysql_old_password and so the best
// available stand-in for a legacy server.
const realHandshake56 = "0a352e362e353100030000003f713e7d7e7e212600fff70802007f8015" +
	"00000000000000000000392c70726a3e37374d5d6c27006d7973716c5f6e61746976655f70617373776f726400"

// Server capabilities as advertised by that server.
const caps56 = uint32(0x807FF7FF)

func TestParseServerHandshakeReal(t *testing.T) {
	p, err := hex.DecodeString(realHandshake56)
	if err != nil {
		t.Fatal(err)
	}
	caps, scramble, err := mysqlwire.ParseServerHandshake(p)
	if err != nil {
		t.Fatalf("ParseServerHandshake: %v", err)
	}
	if caps != caps56 {
		t.Errorf("caps = 0x%08x, want 0x%08x", caps, caps56)
	}
	if caps&mysqlwire.CapDeprecateEOF != 0 {
		t.Error("MySQL 5.6 must not appear to support CLIENT_DEPRECATE_EOF")
	}
	if caps&mysqlwire.CapSecureConnection == 0 {
		t.Error("MySQL 5.6 must appear to support CLIENT_SECURE_CONNECTION")
	}
	wantScramble, _ := hex.DecodeString("3f713e7d7e7e2126392c70726a3e37374d5d6c27")
	if !bytes.Equal(scramble, wantScramble) {
		t.Errorf("scramble = %x, want %x", scramble, wantScramble)
	}
}

// TestParseServerHandshakeShort covers a pre-4.1-shaped greeting: capability
// low bytes only, an 8-byte scramble, nothing after it.
func TestParseServerHandshakeShort(t *testing.T) {
	p := []byte{10}
	p = append(p, "4.0.24\x00"...)
	p = append(p, 1, 0, 0, 0)
	p = append(p, "ABCDEFGH"...)
	p = append(p, 0)
	p = append(p, 0x0F, 0x20) // caps = 0x200F

	caps, scramble, err := mysqlwire.ParseServerHandshake(p)
	if err != nil {
		t.Fatalf("ParseServerHandshake: %v", err)
	}
	if caps != 0x200F {
		t.Errorf("caps = 0x%08x, want 0x0000200F", caps)
	}
	if string(scramble) != "ABCDEFGH" {
		t.Errorf("scramble = %q, want ABCDEFGH", scramble)
	}
}

func TestParseServerHandshakeErrors(t *testing.T) {
	for _, tc := range []struct{ name, packet string }{
		{"empty", ""},
		{"wrong protocol version", "09616263"},
		{"truncated before the scramble", "0a352e362e3531000300"},
		{"truncated before the capabilities", "0a352e362e3531000300000041424344454647480"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := hex.DecodeString(tc.packet)
			if _, _, err := mysqlwire.ParseServerHandshake(p); err == nil {
				t.Error("want an error, got nil")
			}
		})
	}
}

func TestBuildServerHandshakeRoundTrip(t *testing.T) {
	scramble, err := mysqlwire.NewScramble()
	if err != nil {
		t.Fatal(err)
	}
	caps := caps56 & 0x00FFFFFF
	p := mysqlwire.BuildServerHandshake("5.5.62-auth-relay", 42, caps, scramble)

	gotCaps, gotScramble, err := mysqlwire.ParseServerHandshake(p)
	if err != nil {
		t.Fatalf("ParseServerHandshake: %v", err)
	}
	if gotCaps != caps {
		t.Errorf("caps = 0x%08x, want 0x%08x", gotCaps, caps)
	}
	if !bytes.Equal(gotScramble, scramble) {
		t.Errorf("scramble = %x, want %x", gotScramble, scramble)
	}
	if !bytes.Contains(p, []byte(mysqlwire.NativePasswordPlugin)) {
		t.Error("the handshake does not advertise mysql_native_password")
	}
	if !bytes.HasPrefix(p[1:], []byte("5.5.62-auth-relay\x00")) {
		t.Error("the handshake does not carry the configured server version")
	}
}

func TestHandshakeResponseRoundTrip(t *testing.T) {
	authResp := mysqlwire.NativePassword([]byte("12345678901234567890"), "hunter2")
	tests := []struct {
		name string
		caps uint32
		db   string
	}{
		{"secure connection", mysqlwire.CapProtocol41 | mysqlwire.CapSecureConnection, ""},
		{"with schema", mysqlwire.CapProtocol41 | mysqlwire.CapSecureConnection | mysqlwire.CapConnectWithDB, "legacydb"},
		{"pre-secure-connection", mysqlwire.CapProtocol41, ""},
		{"pre-secure-connection with schema", mysqlwire.CapProtocol41 | mysqlwire.CapConnectWithDB, "legacydb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := mysqlwire.BuildHandshakeResponse41(tc.caps, 33, "relayuser", authResp, tc.db, "")
			h, err := mysqlwire.ParseHandshakeResponse41(p)
			if err != nil {
				t.Fatalf("ParseHandshakeResponse41: %v", err)
			}
			if h.Caps != tc.caps {
				t.Errorf("caps = 0x%08x, want 0x%08x", h.Caps, tc.caps)
			}
			if h.User != "relayuser" {
				t.Errorf("user = %q, want relayuser", h.User)
			}
			if h.DB != tc.db {
				t.Errorf("schema = %q, want %q", h.DB, tc.db)
			}
			if h.Charset != 33 {
				t.Errorf("charset = %d, want 33", h.Charset)
			}
			if !bytes.Equal(h.AuthResp, authResp) {
				t.Errorf("auth response = %x, want %x", h.AuthResp, authResp)
			}
		})
	}
}

// TestParseHandshakeResponse41Lenenc covers the length-encoded auth response a
// client sends when it negotiates CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, with a
// schema and a plugin name after it.
func TestParseHandshakeResponse41Lenenc(t *testing.T) {
	caps := mysqlwire.CapProtocol41 | mysqlwire.CapSecureConnection |
		mysqlwire.CapPluginAuthLenenc | mysqlwire.CapConnectWithDB | mysqlwire.CapPluginAuth
	authResp := mysqlwire.NativePassword([]byte("12345678901234567890"), "hunter2")

	p := make([]byte, 0, 128)
	p = append(p, byte(caps), byte(caps>>8), byte(caps>>16), byte(caps>>24))
	p = append(p, 0, 0, 0, 1)
	p = append(p, 45) // utf8mb4_general_ci
	p = append(p, make([]byte, 23)...)
	p = append(p, "appuser\x00"...)
	p = append(p, byte(len(authResp)))
	p = append(p, authResp...)
	p = append(p, "legacydb\x00"...)
	p = append(p, "caching_sha2_password\x00"...)

	h, err := mysqlwire.ParseHandshakeResponse41(p)
	if err != nil {
		t.Fatalf("ParseHandshakeResponse41: %v", err)
	}
	if h.User != "appuser" || h.DB != "legacydb" || h.Charset != 45 {
		t.Errorf("user=%q schema=%q charset=%d", h.User, h.DB, h.Charset)
	}
	if h.Plugin != "caching_sha2_password" {
		t.Errorf("plugin = %q, want caching_sha2_password", h.Plugin)
	}
	if !bytes.Equal(h.AuthResp, authResp) {
		t.Errorf("auth response = %x, want %x", h.AuthResp, authResp)
	}
}

func TestParseHandshakeResponse41Rejects(t *testing.T) {
	pkt := func(caps uint32) []byte {
		p := []byte{byte(caps), byte(caps >> 8), byte(caps >> 16), byte(caps >> 24)}
		p = append(p, 0, 0, 0, 1, 33)
		p = append(p, make([]byte, 23)...)
		return append(p, "u\x00\x00"...)
	}
	if _, err := mysqlwire.ParseHandshakeResponse41(pkt(mysqlwire.CapSecureConnection)); err == nil {
		t.Error("a client without CLIENT_PROTOCOL_41 must be rejected")
	}
	if _, err := mysqlwire.ParseHandshakeResponse41(pkt(mysqlwire.CapProtocol41 | mysqlwire.CapSSL)); err == nil {
		t.Error("an SSLRequest must be rejected, not misparsed as a full response")
	}
	if _, err := mysqlwire.ParseHandshakeResponse41([]byte{1, 2}); err == nil {
		t.Error("a short packet must be rejected")
	}
	// A truncated auth response must not panic or over-read.
	trunc := pkt(mysqlwire.CapProtocol41 | mysqlwire.CapSecureConnection)
	trunc[len(trunc)-1] = 200 // claims 200 bytes of auth data that are not there
	if _, err := mysqlwire.ParseHandshakeResponse41(trunc); err == nil {
		t.Error("a truncated auth response must be rejected")
	}
}

func TestParseAuthSwitch(t *testing.T) {
	// MySQL 5.0: a bare 0xFE meaning "switch to the old password scramble and
	// reuse the scramble you already have".
	plugin, scramble := mysqlwire.ParseAuthSwitch([]byte{0xFE})
	if plugin != "" || scramble != nil {
		t.Errorf("bare 0xFE: plugin=%q scramble=%x, want both empty", plugin, scramble)
	}

	// MySQL 5.5 and later: a full AuthSwitchRequest.
	req := mysqlwire.AuthSwitchRequest(mysqlwire.OldPasswordPlugin, []byte("12345678901234567890"))
	plugin, scramble = mysqlwire.ParseAuthSwitch(req)
	if plugin != mysqlwire.OldPasswordPlugin {
		t.Errorf("plugin = %q, want %s", plugin, mysqlwire.OldPasswordPlugin)
	}
	if string(scramble) != "12345678901234567890" {
		t.Errorf("scramble = %q, want the 20 bytes without the trailing NUL", scramble)
	}
	if !mysqlwire.IsAuthSwitch(req) {
		t.Error("IsAuthSwitch did not recognise an AuthSwitchRequest")
	}
}

// ----------------------------------------------------------------- packets ---

func TestPacketRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payloads := [][]byte{
		{},
		{mysqlwire.ComQuery, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'},
		bytes.Repeat([]byte{0xAB}, 1000),
		bytes.Repeat([]byte{0xCD}, mysqlwire.MaxPayload),
	}
	for i, p := range payloads {
		if err := mysqlwire.WritePacket(&buf, p, byte(i)); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}
	r := bufio.NewReader(&buf)
	for i, want := range payloads {
		got, seq, err := mysqlwire.ReadPacket(r)
		if err != nil {
			t.Fatalf("ReadPacket %d: %v", i, err)
		}
		if seq != byte(i) {
			t.Errorf("packet %d: sequence id = %d, want %d", i, seq, i)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("packet %d: got %d bytes, want %d", i, len(got), len(want))
		}
	}
	if _, _, err := mysqlwire.ReadPacket(r); err == nil {
		t.Error("reading past the end should fail")
	}
}

func TestWritePacketRejectsOversizedPayload(t *testing.T) {
	err := mysqlwire.WritePacket(&bytes.Buffer{}, make([]byte, mysqlwire.MaxPayload+1), 0)
	if err == nil {
		t.Error("a payload above the protocol maximum must be rejected")
	}
}

func TestWritePacketIsASingleWrite(t *testing.T) {
	// A half-written header would desynchronise the peer, so the packet must
	// reach the writer in one call.
	c := &countingWriter{}
	if err := mysqlwire.WritePacket(c, bytes.Repeat([]byte{1}, 5000), 7); err != nil {
		t.Fatal(err)
	}
	if c.writes != 1 {
		t.Errorf("WritePacket made %d writes, want 1", c.writes)
	}
	if c.n != 5004 {
		t.Errorf("wrote %d bytes, want 5004", c.n)
	}
}

type countingWriter struct{ writes, n int }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	c.n += len(p)
	return len(p), nil
}

func TestReadPacketTruncated(t *testing.T) {
	// The header announces 10 bytes but only 3 follow.
	r := bufio.NewReader(bytes.NewReader([]byte{10, 0, 0, 0, 1, 2, 3}))
	if _, _, err := mysqlwire.ReadPacket(r); err == nil {
		t.Error("a truncated packet must be an error")
	}
}

func TestLenencInt(t *testing.T) {
	tests := []struct {
		in   []byte
		want uint64
		adv  int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0xFA}, 250, 1},
		{[]byte{0xFC, 0x34, 0x12}, 0x1234, 3},
		{[]byte{0xFD, 0x56, 0x34, 0x12}, 0x123456, 4},
		{[]byte{0xFE, 8, 7, 6, 5, 4, 3, 2, 1}, 0x0102030405060708, 9},
		{[]byte{}, 0, 0},
		{[]byte{0xFC, 0x34}, 0, 0}, // truncated
		{[]byte{0xFE, 1}, 0, 0},    // truncated
	}
	for _, tc := range tests {
		got, adv := mysqlwire.LenencInt(tc.in)
		if got != tc.want || adv != tc.adv {
			t.Errorf("LenencInt(%x) = (%d, %d), want (%d, %d)", tc.in, got, adv, tc.want, tc.adv)
		}
	}
}

func TestErrPacketAndText(t *testing.T) {
	p := mysqlwire.ErrPacket(1045, "28000", "Access denied for user 'appuser' (relay)")
	if !mysqlwire.IsErr(p) {
		t.Fatalf("error packet starts with 0x%02x, want 0xFF", p[0])
	}
	if code := mysqlwire.ErrCode(p); code != 1045 {
		t.Errorf("code = %d, want 1045", code)
	}
	if p[3] != '#' || string(p[4:9]) != "28000" {
		t.Errorf("SQL state marker or state is wrong: %q", p[3:9])
	}
	if got := mysqlwire.ErrText(p); got != "Access denied for user 'appuser' (relay)" {
		t.Errorf("ErrText = %q", got)
	}
	// An error packet from a pre-4.1 server carries no SQL state.
	old := append([]byte{0xFF, 0x69, 0x04}, "Host blocked"...)
	if got := mysqlwire.ErrText(old); got != "Host blocked" {
		t.Errorf("ErrText(pre-4.1) = %q, want Host blocked", got)
	}
	if got := mysqlwire.ErrCode(old); got != 1129 {
		t.Errorf("ErrCode(pre-4.1) = %d, want 1129", got)
	}
	if got := mysqlwire.ErrText([]byte{0xFF}); got != "unknown error" {
		t.Errorf("ErrText(truncated) = %q", got)
	}
}

func TestOKPacket(t *testing.T) {
	p := mysqlwire.OKPacket()
	if !mysqlwire.IsOK(p) {
		t.Errorf("OK packet starts with 0x%02x, want 0x00", p[0])
	}
	if len(p) != 7 {
		t.Errorf("OK packet is %d bytes, want 7", len(p))
	}
	if status := uint16(p[3]) | uint16(p[4])<<8; status != 0x0002 {
		t.Errorf("status flags = 0x%04x, want SERVER_STATUS_AUTOCOMMIT", status)
	}
	if mysqlwire.IsEOF(p) || mysqlwire.IsErr(p) {
		t.Error("an OK packet must not be mistaken for EOF or ERR")
	}
}

// TestIsEOF checks the rule that separates an EOF marker from a row whose
// first column length happens to encode as 0xFE.
func TestIsEOF(t *testing.T) {
	if !mysqlwire.IsEOF([]byte{0xFE, 0, 0, 0x02, 0}) {
		t.Error("a 5-byte 0xFE packet is an EOF marker")
	}
	if !mysqlwire.IsEOF([]byte{0xFE}) {
		t.Error("a bare 0xFE is an EOF marker")
	}
	if mysqlwire.IsEOF(append([]byte{0xFE}, bytes.Repeat([]byte{1}, 20)...)) {
		t.Error("a long packet starting with 0xFE is a row, not EOF")
	}
	if mysqlwire.IsEOF(nil) {
		t.Error("an empty packet is not EOF")
	}
}
