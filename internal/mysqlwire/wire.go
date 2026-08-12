// Package mysqlwire implements the parts of the MySQL client/server protocol
// the relay needs: packet framing, the connection-phase handshakes, and the two
// password scrambles (4.1 native and pre-4.1 "old").
//
// It is deliberately small. Everything after authentication is opaque bytes to
// the relay, so nothing here parses result sets, rows or SQL.
package mysqlwire

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Capability flags, as sent in the low and high 16 bits of the handshake.
const (
	CapLongPassword     uint32 = 1 << 0
	CapFoundRows        uint32 = 1 << 1
	CapLongFlag         uint32 = 1 << 2
	CapConnectWithDB    uint32 = 1 << 3
	CapNoSchema         uint32 = 1 << 4
	CapCompress         uint32 = 1 << 5
	CapLocalFiles       uint32 = 1 << 7
	CapIgnoreSpace      uint32 = 1 << 8
	CapProtocol41       uint32 = 1 << 9
	CapInteractive      uint32 = 1 << 10
	CapSSL              uint32 = 1 << 11
	CapTransactions     uint32 = 1 << 13
	CapSecureConnection uint32 = 1 << 15
	CapMultiStatements  uint32 = 1 << 16
	CapMultiResults     uint32 = 1 << 17
	CapPSMultiResults   uint32 = 1 << 18
	CapPluginAuth       uint32 = 1 << 19
	CapConnectAttrs     uint32 = 1 << 20
	CapPluginAuthLenenc uint32 = 1 << 21
	CapExpiredPasswords uint32 = 1 << 22
	CapSessionTrack     uint32 = 1 << 23
	CapDeprecateEOF     uint32 = 1 << 24
	CapOptionalMetadata uint32 = 1 << 25
	CapZstd             uint32 = 1 << 26
	CapQueryAttributes  uint32 = 1 << 27
)

// Command bytes the relay recognises. Everything else is opaque to it.
const (
	ComQuit  = 0x01
	ComQuery = 0x03
)

// MaxPayload is the largest payload a single MySQL packet can carry. A payload
// of exactly this size means the packet is continued by the next one.
const MaxPayload = 0xFFFFFF

// Authentication plugin names.
const (
	NativePasswordPlugin = "mysql_native_password"
	OldPasswordPlugin    = "mysql_old_password"
)

// Response packet first bytes.
const (
	respOK         = 0x00
	respEOF        = 0xFE
	respErr        = 0xFF
	protocolVer10  = 10
	utf8GeneralCI  = 33
	statusAutocmit = 0x0002
)

// ReadPacket reads one packet and returns its payload and sequence id. A
// payload of exactly MaxPayload bytes means the caller must read the next
// packet to get the rest.
func ReadPacket(r *bufio.Reader) ([]byte, byte, error) {
	return ReadPacketInto(r, nil)
}

// ReadPacketInto is ReadPacket with a caller-supplied buffer. If buf has the
// capacity, the payload is read into it and the returned slice aliases it;
// otherwise a new buffer is allocated. Callers that forward each packet before
// reading the next one can pass the previous payload back in and pay no
// allocation per packet at all.
func ReadPacketInto(r *bufio.Reader, buf []byte) ([]byte, byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if cap(buf) >= n {
		buf = buf[:n]
	} else {
		buf = make([]byte, n)
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, 0, err
	}
	return buf, hdr[3], nil
}

// WritePacket frames a payload and writes it in a single Write, so that a
// packet never reaches the wire half-formed.
func WritePacket(w io.Writer, payload []byte, seq byte) error {
	n := len(payload)
	if n > MaxPayload {
		return fmt.Errorf("packet payload of %d bytes exceeds the protocol maximum", n)
	}
	buf := make([]byte, 0, 4+n)
	buf = append(buf, byte(n), byte(n>>8), byte(n>>16), seq)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// IsOK reports whether a response packet is an OK packet.
func IsOK(p []byte) bool { return len(p) > 0 && p[0] == respOK }

// IsErr reports whether a response packet is an ERR packet.
func IsErr(p []byte) bool { return len(p) > 0 && p[0] == respErr }

// IsEOF reports whether a packet is an EOF marker rather than a row that
// happens to start with 0xFE. A length-encoded integer of 0xFE always needs at
// least nine bytes, so the length is what distinguishes them.
func IsEOF(p []byte) bool { return len(p) > 0 && len(p) < 9 && p[0] == respEOF }

// IsAuthSwitch reports whether a connection-phase packet asks the client to
// switch authentication method.
func IsAuthSwitch(p []byte) bool { return len(p) > 0 && p[0] == respEOF }

// OKPacket is an OK for a protocol-41 session: header, affected_rows=0,
// last_insert_id=0, status=autocommit, warnings=0.
func OKPacket() []byte {
	return []byte{respOK, 0x00, 0x00, statusAutocmit, 0x00, 0x00, 0x00}
}

// ErrPacket builds an ERR packet carrying a SQL state, the form every
// protocol-41 client understands.
func ErrPacket(code uint16, state, msg string) []byte {
	b := []byte{respErr, byte(code), byte(code >> 8), '#'}
	b = append(b, []byte(state)...)
	return append(b, []byte(msg)...)
}

// ErrText extracts the human-readable message from an ERR packet, tolerating
// the pre-4.1 form that carries no SQL state.
func ErrText(p []byte) string {
	if len(p) > 9 && p[3] == '#' {
		return string(p[9:])
	}
	if len(p) > 3 {
		return string(p[3:])
	}
	return "unknown error"
}

// ErrCode extracts the error number from an ERR packet, or 0.
func ErrCode(p []byte) uint16 {
	if len(p) < 3 {
		return 0
	}
	return uint16(p[1]) | uint16(p[2])<<8
}

// LenencInt decodes a length-encoded integer, returning the value and how many
// bytes it occupied. An advance of 0 means the input was truncated.
func LenencInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch {
	case b[0] < 0xFB:
		return uint64(b[0]), 1
	case b[0] == 0xFC && len(b) >= 3:
		return uint64(b[1]) | uint64(b[2])<<8, 3
	case b[0] == 0xFD && len(b) >= 4:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4
	case b[0] == 0xFE && len(b) >= 9:
		var v uint64
		for i := 0; i < 8; i++ {
			v |= uint64(b[1+i]) << (8 * i)
		}
		return v, 9
	}
	return 0, 0
}

// NewScramble returns 20 random bytes with no NUL among them: the protocol
// treats auth-plugin-data as a NUL-terminated string.
func NewScramble() ([]byte, error) {
	s := make([]byte, 20)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	for i, b := range s {
		s[i] = b%94 + 33 // printable ASCII, never 0
	}
	return s, nil
}

// ParseServerHandshake extracts the capability flags and the scramble from an
// Initial Handshake Packet (protocol version 10). It handles both the modern
// layout and the shorter one older servers send.
func ParseServerHandshake(p []byte) (caps uint32, scramble []byte, err error) {
	if len(p) == 0 {
		return 0, nil, errors.New("empty handshake packet")
	}
	if p[0] != protocolVer10 {
		return 0, nil, fmt.Errorf("unsupported handshake protocol %d", p[0])
	}
	i := 1
	for i < len(p) && p[i] != 0 { // server version
		i++
	}
	i++    // NUL
	i += 4 // connection id
	if i+8 > len(p) {
		return 0, nil, errors.New("short handshake (scramble)")
	}
	scramble = append([]byte{}, p[i:i+8]...)
	i += 8
	i++ // filler
	if i+2 > len(p) {
		return 0, nil, errors.New("short handshake (capabilities)")
	}
	caps = uint32(p[i]) | uint32(p[i+1])<<8
	i += 2
	if i < len(p) {
		i++    // charset
		i += 2 // status flags
		if i+2 <= len(p) {
			caps |= (uint32(p[i]) | uint32(p[i+1])<<8) << 16
			i += 2
		}
		// auth-plugin-data length (1) + reserved (10). MySQL 5.0 sends 13 zero
		// bytes in total here, so the offsets coincide.
		i += 11
		if i+12 <= len(p) {
			scramble = append(scramble, p[i:i+12]...)
		}
	}
	return caps, scramble, nil
}

// ParseServerVersion returns the version string from an Initial Handshake
// Packet, or "" if the packet is not one. It is separate from
// ParseServerHandshake because the version matters only to callers deciding
// what a particular server supports, whereas the capabilities and scramble are
// needed to authenticate at all.
//
// The string is whatever the server chose to call itself, including any suffix:
// "5.0.77", "5.6.51-log", or MariaDB's compatibility form
// "5.5.5-10.11.2-MariaDB". Interpreting it is the caller's problem.
func ParseServerVersion(p []byte) string {
	if len(p) < 2 || p[0] != protocolVer10 {
		return ""
	}
	for i := 1; i < len(p); i++ {
		if p[i] == 0 {
			return string(p[1:i])
		}
	}
	return ""
}

// BuildServerHandshake builds the Initial Handshake Packet the relay sends to
// its own clients. It always names mysql_native_password.
func BuildServerHandshake(version string, connID, caps uint32, scramble []byte) []byte {
	b := []byte{protocolVer10}
	b = append(b, []byte(version)...)
	b = append(b, 0)
	b = append(b, byte(connID), byte(connID>>8), byte(connID>>16), byte(connID>>24))
	b = append(b, scramble[:8]...)
	b = append(b, 0)                              // filler
	b = append(b, byte(caps), byte(caps>>8))      // capability flags, lower
	b = append(b, utf8GeneralCI)                  // default charset
	b = append(b, statusAutocmit, 0x00)           // status flags
	b = append(b, byte(caps>>16), byte(caps>>24)) // capability flags, upper
	b = append(b, byte(len(scramble)+1))          // auth-plugin-data length
	b = append(b, make([]byte, 10)...)            // reserved
	b = append(b, scramble[8:]...)                // remainder of the scramble
	b = append(b, 0)
	b = append(b, []byte(NativePasswordPlugin)...)
	return append(b, 0)
}

// AuthSwitchRequest asks a client to authenticate again with another plugin.
func AuthSwitchRequest(plugin string, scramble []byte) []byte {
	b := []byte{respEOF}
	b = append(b, []byte(plugin)...)
	b = append(b, 0)
	b = append(b, scramble...)
	return append(b, 0)
}

// ParseAuthSwitch reads an AuthSwitchRequest: 0xFE, plugin name, scramble. A
// bare 0xFE is MySQL 5.0's way of saying "switch to the old password scramble
// and reuse the scramble you already have"; it yields an empty plugin name.
func ParseAuthSwitch(p []byte) (plugin string, scramble []byte) {
	if len(p) < 2 {
		return "", nil
	}
	i := 1
	start := i
	for i < len(p) && p[i] != 0 {
		i++
	}
	plugin = string(p[start:i])
	i++
	if i < len(p) {
		scramble = p[i:]
		if n := len(scramble); n > 0 && scramble[n-1] == 0 { // NUL-terminated
			scramble = scramble[:n-1]
		}
	}
	return plugin, scramble
}

// HandshakeResponse is a parsed Protocol::HandshakeResponse41.
type HandshakeResponse struct {
	Caps     uint32
	Charset  byte
	User     string
	DB       string
	Plugin   string
	AuthResp []byte
}

// readNulString reads a NUL-terminated string starting at i. It returns the
// string and the offset just past the terminator, which is always within
// bounds, so callers can slice at it safely.
func readNulString(p []byte, i int) (string, int, error) {
	if i > len(p) {
		return "", len(p), errors.New("truncated packet")
	}
	for j := i; j < len(p); j++ {
		if p[j] == 0 {
			return string(p[i:j]), j + 1, nil
		}
	}
	return "", len(p), errors.New("unterminated string")
}

// ParseHandshakeResponse41 parses a client's reply to the initial handshake.
// It requires CLIENT_PROTOCOL_41 and rejects an SSLRequest, both of which the
// relay cannot serve.
//
// Every offset is checked before it is used. This runs before authentication,
// on bytes from anyone who can open a socket, so a malformed packet has to
// come back as an error rather than a panic — an unterminated username in a
// packet claiming CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA used to take the whole
// process down, and with it every other connection it was relaying.
func ParseHandshakeResponse41(p []byte) (*HandshakeResponse, error) {
	if len(p) < 4 {
		return nil, errors.New("short handshake response")
	}
	h := &HandshakeResponse{Caps: uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16 | uint32(p[3])<<24}
	if h.Caps&CapProtocol41 == 0 {
		return nil, errors.New("client did not negotiate the 4.1 protocol; this relay requires it")
	}
	if h.Caps&CapSSL != 0 {
		return nil, errors.New("client requested TLS, which the relay does not offer")
	}
	// caps(4) + max packet(4) + charset(1) + reserved(23)
	const headerLen = 32
	if len(p) < headerLen {
		return nil, errors.New("short handshake response")
	}
	h.Charset = p[8]

	user, i, err := readNulString(p, headerLen)
	if err != nil {
		return nil, fmt.Errorf("username: %w", err)
	}
	h.User = user

	switch {
	case h.Caps&CapPluginAuthLenenc != 0:
		n, adv := LenencInt(p[i:])
		if adv == 0 {
			return nil, errors.New("truncated auth response length")
		}
		i += adv
		if n > uint64(len(p)-i) {
			return nil, errors.New("truncated auth response")
		}
		h.AuthResp = p[i : i+int(n)]
		i += int(n)
	case h.Caps&CapSecureConnection != 0:
		if i >= len(p) {
			return nil, errors.New("missing auth response")
		}
		n := int(p[i])
		i++
		if n > len(p)-i {
			return nil, errors.New("truncated auth response")
		}
		h.AuthResp = p[i : i+n]
		i += n
	default:
		resp, next, err := readNulString(p, i)
		if err != nil {
			return nil, fmt.Errorf("auth response: %w", err)
		}
		h.AuthResp, i = []byte(resp), next
	}

	// The schema and the plugin name are optional tails. A client that sets the
	// capability but sends nothing is tolerated: the field is simply empty.
	if h.Caps&CapConnectWithDB != 0 && i < len(p) {
		db, next, err := readNulString(p, i)
		if err != nil {
			return nil, fmt.Errorf("schema: %w", err)
		}
		h.DB, i = db, next
	}
	if h.Caps&CapPluginAuth != 0 && i < len(p) {
		// An unterminated plugin name is not worth refusing a connection over:
		// what remains of the packet is the name.
		plugin, _, err := readNulString(p, i)
		if err != nil {
			plugin = string(p[i:])
		}
		h.Plugin = plugin
	}
	return h, nil
}

// BuildHandshakeResponse41 builds the reply the relay sends to the legacy
// server. The auth-response encoding follows the capabilities in caps, so it
// is also correct against a server too old for CLIENT_SECURE_CONNECTION.
//
// plugin names the authentication method being attempted and is written only
// when caps has CLIENT_PLUGIN_AUTH. A server that advertises CLIENT_PLUGIN_AUTH
// requires both — MySQL 5.6 answers "Bad handshake" (error 1043) to a response
// that omits the flag, even for an account whose password predates plugins.
func BuildHandshakeResponse41(caps uint32, charset byte, user string, authResp []byte, db, plugin string) []byte {
	b := make([]byte, 0, 64)
	b = append(b, byte(caps), byte(caps>>8), byte(caps>>16), byte(caps>>24))
	b = append(b, 0x00, 0x00, 0x00, 0x01) // max packet size: 16 MB
	b = append(b, charset)
	b = append(b, make([]byte, 23)...) // reserved
	b = append(b, []byte(user)...)
	b = append(b, 0)
	if caps&CapSecureConnection != 0 {
		b = append(b, byte(len(authResp)))
		b = append(b, authResp...)
	} else {
		b = append(b, authResp...)
		b = append(b, 0)
	}
	if caps&CapConnectWithDB != 0 {
		b = append(b, []byte(db)...)
		b = append(b, 0)
	}
	if caps&CapPluginAuth != 0 {
		b = append(b, []byte(plugin)...)
		b = append(b, 0)
	}
	return b
}
