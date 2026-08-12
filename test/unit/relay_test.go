package unit

import (
	"strings"
	"testing"

	"github.com/ralforion/mysql-old-password-proxy/internal/mysqlwire"
	"github.com/ralforion/mysql-old-password-proxy/internal/relay"
)

// TestFramingSafeExcludesDangerous guards the design's central claim: nothing
// that alters post-authentication framing may be relayed end to end.
func TestFramingSafeExcludesDangerous(t *testing.T) {
	forbidden := map[string]uint32{
		"CLIENT_DEPRECATE_EOF":                 mysqlwire.CapDeprecateEOF,
		"CLIENT_SESSION_TRACK":                 mysqlwire.CapSessionTrack,
		"CLIENT_COMPRESS":                      mysqlwire.CapCompress,
		"CLIENT_ZSTD_COMPRESSION_ALGORITHM":    mysqlwire.CapZstd,
		"CLIENT_SSL":                           mysqlwire.CapSSL,
		"CLIENT_LOCAL_FILES":                   mysqlwire.CapLocalFiles,
		"CLIENT_OPTIONAL_RESULTSET_METADATA":   mysqlwire.CapOptionalMetadata,
		"CLIENT_QUERY_ATTRIBUTES":              mysqlwire.CapQueryAttributes,
		"CLIENT_PLUGIN_AUTH_LENENC_CLIENTDATA": mysqlwire.CapPluginAuthLenenc,
	}
	for name, bit := range forbidden {
		if relay.FramingSafe&bit != 0 {
			t.Errorf("FramingSafe must not contain %s (0x%08x)", name, bit)
		}
	}
	if relay.FramingSafe&mysqlwire.CapProtocol41 == 0 {
		t.Error("FramingSafe must contain CLIENT_PROTOCOL_41")
	}
	// Every dangerous flag must be one CheckCapabilities actually looks at.
	for name, bit := range forbidden {
		if bit == mysqlwire.CapSSL || bit == mysqlwire.CapPluginAuthLenenc {
			continue // connection-phase only: they do not change relayed framing
		}
		if relay.FramingRelevant&bit == 0 {
			t.Errorf("FramingRelevant must contain %s (0x%08x), or the check cannot catch it", name, bit)
		}
	}
}

// offerFor is the capability set the relay advertises to a client, given what
// the backend was last seen to support.
func offerFor(serverCaps uint32) uint32 {
	return (serverCaps & relay.FramingSafe) | mysqlwire.CapProtocol41 |
		mysqlwire.CapSecureConnection | mysqlwire.CapPluginAuth
}

func TestCheckCapabilities(t *testing.T) {
	const client = relay.FramingSafe | mysqlwire.CapPluginAuth
	// Real capability sets sent by stock clients, measured through the proxy.
	// They all claim capabilities the server never advertised, which a real
	// MySQL server ignores rather than refusing.
	const (
		mysql56Client = 0x003FA28D
		mysql80Client = 0x19BFA28D
		mariadbClient = 0x00BFA28D
	)

	tests := []struct {
		name       string
		clientCaps uint32
		offered    uint32
		serverCaps uint32
		wantErr    bool
	}{
		{"typical client against 5.6", client, offerFor(caps56), caps56, false},
		{"client asking for less", mysqlwire.CapProtocol41 | mysqlwire.CapSecureConnection, offerFor(caps56), caps56, false},
		{"auth-only bits are not framing", client | mysqlwire.CapConnectAttrs | mysqlwire.CapPluginAuthLenenc, offerFor(caps56), caps56, false},

		// Stock clients set bits the relay never offered. They must be ignored,
		// exactly as a real server ignores them, or no modern client could
		// connect at all.
		{"stock mysql 5.6 client", mysql56Client, offerFor(caps56), caps56, false},
		{"stock mysql 8.0 client (DEPRECATE_EOF, SESSION_TRACK, QUERY_ATTRIBUTES)", mysql80Client, offerFor(caps56), caps56, false},
		{"stock mariadb client", mariadbClient, offerFor(caps56), caps56, false},
		{"a client claiming everything", 0xFFFFFFFF, offerFor(caps56), caps56, false},

		// The case the check exists for: the backend was restarted onto a
		// version with fewer capabilities than the offer was built from, so the
		// two halves would now frame result sets differently.
		{"backend lost MULTI_RESULTS since the probe", client, offerFor(caps56), caps56 &^ mysqlwire.CapMultiResults, true},
		{"backend lost MULTI_STATEMENTS since the probe", client, offerFor(caps56), caps56 &^ mysqlwire.CapMultiStatements, true},
		{"backend lost PS_MULTI_RESULTS since the probe", client, offerFor(caps56), caps56 &^ mysqlwire.CapPSMultiResults, true},
		{"backend loss the client did not take up", mysqlwire.CapProtocol41 | mysqlwire.CapSecureConnection,
			offerFor(caps56), caps56 &^ mysqlwire.CapMultiResults, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := relay.CheckCapabilities(tc.clientCaps, tc.offered, tc.serverCaps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckCapabilities = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestEffectiveCapsExcludeDangerousFlags is the property the whole design rests
// on: whatever a client claims, the capabilities actually in force are bounded
// by the relay's offer, which never contains a framing-changing flag.
func TestEffectiveCapsExcludeDangerousFlags(t *testing.T) {
	dangerous := mysqlwire.CapDeprecateEOF | mysqlwire.CapSessionTrack |
		mysqlwire.CapCompress | mysqlwire.CapZstd | mysqlwire.CapQueryAttributes |
		mysqlwire.CapOptionalMetadata | mysqlwire.CapLocalFiles | mysqlwire.CapSSL
	for _, serverCaps := range []uint32{caps56, 0xFFFFFFFF, 0x0000F7FF, mysqlwire.CapProtocol41} {
		effective := relay.EffectiveCaps(0xFFFFFFFF, offerFor(serverCaps))
		if bad := effective & dangerous; bad != 0 {
			t.Errorf("server caps 0x%08x: a client claiming everything ends up with 0x%08x in force",
				serverCaps, bad)
		}
	}
}

// TestOfferedCapsAreAcceptable checks that, for any backend, a client that
// accepts the relay's whole offer is never then refused by the invariant check.
func TestOfferedCapsAreAcceptable(t *testing.T) {
	for _, serverCaps := range []uint32{caps56, 0xFFFFFFFF, 0x0000A20F, mysqlwire.CapProtocol41, 0} {
		offered := offerFor(serverCaps)
		err := relay.CheckCapabilities(offered, offered, serverCaps)
		if serverCaps&mysqlwire.CapProtocol41 == 0 {
			// A backend without CLIENT_PROTOCOL_41 is refused earlier, when the
			// backend handshake is parsed; the invariant may fail here.
			continue
		}
		if err != nil {
			t.Errorf("server caps 0x%08x: a client accepting the whole offer is rejected: %v", serverCaps, err)
		}
	}
}

// ---------------------------------------------------------------- rewrites ---

func TestRewriteUTF8MB4(t *testing.T) {
	tests := []struct{ in, want string }{
		{"SET NAMES utf8mb4", "SET NAMES utf8"},
		{"SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci", "SET NAMES utf8 COLLATE utf8_unicode_ci"},
		// The replacement is always lowercase; charset names are not case sensitive.
		{"set names UTF8MB4", "set names utf8"},
		{"SET character_set_client = Utf8mb4", "SET character_set_client = utf8"},
		{"SELECT 1", "SELECT 1"},
		{"SELECT 'utf8'", "SELECT 'utf8'"},
		{"", ""},
		// Documented wart: the literal is rewritten inside data too.
		{"SELECT 'utf8mb4'", "SELECT 'utf8'"},
	}
	for _, tc := range tests {
		if got := relay.RewriteUTF8MB4(tc.in); got != tc.want {
			t.Errorf("RewriteUTF8MB4(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRewriteUTF8MB4NonASCII checks the byte-wise rewrite does not damage
// multi-byte UTF-8 elsewhere in the statement.
func TestRewriteUTF8MB4NonASCII(t *testing.T) {
	in := "SET NAMES utf8mb4 /* Grüße, 日本語 */"
	want := "SET NAMES utf8 /* Grüße, 日本語 */"
	if got := relay.RewriteUTF8MB4(in); got != want {
		t.Errorf("RewriteUTF8MB4 mangled non-ASCII: %q", got)
	}
}

func TestRewriteDatetimePrecision(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{
			// The shape MariaDB Connector/J 3.x sends from getColumns().
			name: "connector/j getColumns expression",
			in:   "SELECT x FROM INFORMATION_SCHEMA.COLUMNS WHERE IF(DATETIME_PRECISION = 0, 19, CAST(20 + DATETIME_PRECISION as signed integer))",
			want: "SELECT x FROM INFORMATION_SCHEMA.COLUMNS WHERE IF(0 = 0, 19, CAST(20 + 0 as signed integer))",
		},
		{
			name: "lowercase table and column",
			in:   "select datetime_precision from information_schema.columns",
			want: "select 0 from information_schema.columns",
		},
		{
			name: "cast form",
			in:   "SELECT CAST(DATETIME_PRECISION as signed integer) FROM information_schema.COLUMNS",
			want: "SELECT CAST(0 as signed integer) FROM information_schema.COLUMNS",
		},
		{
			// Scoped to information_schema: an application table keeping a
			// column of that name is none of the proxy's business.
			name: "untouched outside information_schema",
			in:   "SELECT DATETIME_PRECISION FROM my_metadata_table",
			want: "SELECT DATETIME_PRECISION FROM my_metadata_table",
		},
		{
			name: "identifier boundary, longer name",
			in:   "SELECT MY_DATETIME_PRECISION_X FROM information_schema.COLUMNS",
			want: "SELECT MY_DATETIME_PRECISION_X FROM information_schema.COLUMNS",
		},
		{
			// A quoted identifier must not become `0`, which names a column "0".
			name: "backtick quoted left alone",
			in:   "SELECT `DATETIME_PRECISION` FROM information_schema.COLUMNS",
			want: "SELECT `DATETIME_PRECISION` FROM information_schema.COLUMNS",
		},
		{
			name: "no column present",
			in:   "SELECT TABLE_NAME FROM information_schema.TABLES",
			want: "SELECT TABLE_NAME FROM information_schema.TABLES",
		},
		{name: "empty", in: "", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := relay.RewriteDatetimePrecision(tc.in); got != tc.want {
				t.Errorf("RewriteDatetimePrecision(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRewriteDatetimePrecisionSubstitutesZeroNotNull pins the choice of 0 over
// NULL. The driver computes column sizes arithmetically from this value, so
// NULL would propagate through the comparison and the CAST and every temporal
// column would report a NULL size — a subtler failure than the one being fixed.
func TestRewriteDatetimePrecisionSubstitutesZeroNotNull(t *testing.T) {
	in := "SELECT IF(DATETIME_PRECISION = 0, 19, 20) FROM information_schema.COLUMNS"
	got := relay.RewriteDatetimePrecision(in)
	if strings.Contains(strings.ToUpper(got), "NULL") {
		t.Errorf("substituted NULL, want 0: %q", got)
	}
	if !strings.Contains(got, "IF(0 = 0, 19, 20)") {
		t.Errorf("got %q, want the literal 0 substituted", got)
	}
}

func TestBackendCharset(t *testing.T) {
	// utf8mb4 collations must come down to utf8_general_ci for a 5.0 server.
	for _, cs := range []byte{45, 46, 224, 246, 255} {
		if got := relay.BackendCharset(cs, true); got != 33 {
			t.Errorf("BackendCharset(%d) = %d, want 33 (utf8_general_ci)", cs, got)
		}
	}
	// latin1_swedish_ci, utf8_general_ci, binary, utf8_unicode_ci: passed through.
	for _, cs := range []byte{8, 33, 63, 192} {
		if got := relay.BackendCharset(cs, true); got != cs {
			t.Errorf("BackendCharset(%d) = %d, want it passed through", cs, got)
		}
	}
	if got := relay.BackendCharset(45, false); got != 45 {
		t.Errorf("with rewriting off, BackendCharset(45) = %d, want 45", got)
	}
}

// ------------------------------------------------------------------ config ---

func TestConfigValidation(t *testing.T) {
	full := relay.Config{
		Backend: "legacy-mysql.internal:3306", BackendUser: "legacy", BackendPass: "pw", FrontendPass: "fpw",
	}
	tests := []struct {
		name    string
		mutate  func(*relay.Config)
		wantErr bool
	}{
		{"complete", func(*relay.Config) {}, false},
		{"no backend", func(c *relay.Config) { c.Backend = "" }, true},
		{"no backend user", func(c *relay.Config) { c.BackendUser = "" }, true},
		{"no backend password", func(c *relay.Config) { c.BackendPass = "" }, true},
		{"no frontend password", func(c *relay.Config) { c.FrontendPass = "" }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full
			tc.mutate(&cfg)
			_, err := relay.New(cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	srv, err := relay.New(relay.Config{
		Backend: "legacy-mysql.internal:3306", BackendUser: "legacy", BackendPass: "pw", FrontendPass: "fpw",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := srv.Config()
	// The frontend user defaults to the backend user, as documented.
	if cfg.FrontendUser != "legacy" {
		t.Errorf("FrontendUser = %q, want it to default to the backend user", cfg.FrontendUser)
	}
	if cfg.ServerVersion == "" || cfg.DialTimeout == 0 || cfg.AuthTimeout == 0 || cfg.Logger == nil {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	// Capabilities are unknown until the backend has been reached.
	if _, known := srv.BackendCaps(); known {
		t.Error("backend capabilities must start out unknown")
	}
}

// ------------------------------------------------- DATETIME_PRECISION gate ---

// TestBackendHasDatetimePrecision pins which servers the shim applies to.
// information_schema.COLUMNS.DATETIME_PRECISION arrived in MySQL 5.6 and, with
// the rest of fractional-second support, in MariaDB 5.3.
func TestBackendHasDatetimePrecision(t *testing.T) {
	tests := []struct {
		version         string
		has, recognised bool
	}{
		// The servers this proxy exists for.
		{"5.0.77", false, true},
		{"5.0.96-community", false, true},
		{"5.1.73", false, true},
		{"5.5.62", false, true},
		{"5.5.62-log", false, true},
		// MySQL from 5.6 on has the column.
		{"5.6.51", true, true},
		{"5.6.51-log", true, true},
		{"5.7.44", true, true},
		{"8.0.36", true, true},
		{"8.4.0", true, true},
		{"9.1.0", true, true},
		// MariaDB reports itself two ways. The "5.5.5-" prefix is a
		// compatibility marker, not a version: read literally it would make
		// 10.11 look like 5.5 and wrongly trigger the shim.
		{"10.11.2-MariaDB", true, true},
		{"5.5.5-10.11.2-MariaDB", true, true},
		{"5.5.5-10.6.12-MariaDB-1:10.6.12+maria~ubu2004", true, true},
		{"5.3.12-MariaDB", true, true},
		{"5.2.14-MariaDB", false, true},
		{"5.1.67-MariaDB", false, true},
		// Anything unreadable is reported as having the column, so the failure
		// is a loud "Unknown column" rather than silently wrong metadata.
		{"", true, false},
		{"not-a-version", true, false},
		{"5", true, false},
		{"5.x", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			has, recognised := relay.BackendHasDatetimePrecision(tc.version)
			if has != tc.has || recognised != tc.recognised {
				t.Errorf("BackendHasDatetimePrecision(%q) = (%v, %v), want (%v, %v)",
					tc.version, has, recognised, tc.has, tc.recognised)
			}
		})
	}
}

func TestParseDTPMode(t *testing.T) {
	for in, want := range map[string]relay.DTPMode{
		"":       relay.DTPAuto,
		"auto":   relay.DTPAuto,
		"AUTO":   relay.DTPAuto,
		" auto ": relay.DTPAuto,
		"always": relay.DTPAlways,
		"on":     relay.DTPAlways,
		"never":  relay.DTPNever,
		"off":    relay.DTPNever,
		// The flag was a boolean before the version gate existed; both spellings
		// keep working, and mean what they used to.
		"true":  relay.DTPAlways,
		"false": relay.DTPNever,
	} {
		got, err := relay.ParseDTPMode(in)
		if err != nil {
			t.Errorf("ParseDTPMode(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseDTPMode(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := relay.ParseDTPMode("sometimes"); err == nil {
		t.Error("an unknown mode must be rejected")
	}
}

// TestRewriteUTF8MB4Collations covers the collation suffix, which cannot simply
// be renamed: utf8mb4 has collations utf8 never had, and utf8_0900_ai_ci is not
// a collation on any server.
func TestRewriteUTF8MB4Collations(t *testing.T) {
	tests := []struct{ name, in, want string }{
		// Suffixes the old utf8 character set really has are carried across.
		{"unicode_ci", "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
			"SET NAMES utf8 COLLATE utf8_unicode_ci"},
		{"general_ci", "SET NAMES utf8mb4 COLLATE utf8mb4_general_ci",
			"SET NAMES utf8 COLLATE utf8_general_ci"},
		{"bin", "SET NAMES utf8mb4 COLLATE utf8mb4_bin", "SET NAMES utf8 COLLATE utf8_bin"},
		{"a language collation", "SET NAMES utf8mb4 COLLATE utf8mb4_turkish_ci",
			"SET NAMES utf8 COLLATE utf8_turkish_ci"},

		// Anything else becomes utf8_general_ci. Renaming would invent a
		// collation that has never existed and the server would refuse it.
		{"MySQL 8.0 default", "SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci",
			"SET NAMES utf8 COLLATE utf8_general_ci"},
		{"MySQL 8.0 case sensitive", "SET NAMES utf8mb4 COLLATE utf8mb4_0900_as_cs",
			"SET NAMES utf8 COLLATE utf8_general_ci"},
		{"MariaDB 11 UCA", "SET NAMES utf8mb4 COLLATE utf8mb4_uca1400_ai_ci",
			"SET NAMES utf8 COLLATE utf8_general_ci"},
		{"unicode_520_ci, added after 5.0", "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_520_ci",
			"SET NAMES utf8 COLLATE utf8_general_ci"},
		{"a session variable", "SET collation_connection = utf8mb4_0900_ai_ci",
			"SET collation_connection = utf8_general_ci"},

		// A bare charset name has no suffix to consider.
		{"bare", "SET NAMES utf8mb4", "SET NAMES utf8"},
		{"in CONVERT", "SELECT CONVERT('x' USING utf8mb4)", "SELECT CONVERT('x' USING utf8)"},
		{"followed by punctuation", "SET NAMES utf8mb4;", "SET NAMES utf8;"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := relay.RewriteUTF8MB4(tc.in); got != tc.want {
				t.Errorf("RewriteUTF8MB4(%q) =\n %q\nwant\n %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRewritesSurviveUnicode guards both rewrites against a folding bug that
// used to panic the process. strings.ToLower changes byte lengths — U+212A
// KELVIN SIGN is three bytes and lowercases to a one-byte "k" — so indexing the
// original query with offsets from a folded copy read out of bounds.
func TestRewritesSurviveUnicode(t *testing.T) {
	runes := []string{
		"K",     // KELVIN SIGN, folds shorter
		"İ",     // LATIN CAPITAL I WITH DOT ABOVE, folds longer
		"ẞ",     // LATIN CAPITAL SHARP S
		"日本語",   // no case at all
		"Grüße", // ordinary accented text
		"АБ",    // Cyrillic
	}
	for _, r := range runes {
		t.Run(r, func(t *testing.T) {
			pad := strings.Repeat(r, 40)
			for _, q := range []string{
				"SET NAMES utf8mb4 /* " + pad + " */",
				"/* " + pad + " */ SET NAMES utf8mb4",
				"SELECT '" + pad + "' FROM information_schema.COLUMNS WHERE DATETIME_PRECISION > 0",
				pad + "utf8mb4" + pad,
			} {
				// The result is not what is being checked here; not panicking,
				// and not corrupting the surrounding text, is.
				got := relay.RewriteUTF8MB4(q)
				if !strings.Contains(got, pad) {
					t.Errorf("RewriteUTF8MB4 damaged the surrounding text: %q", got)
				}
				if got := relay.RewriteDatetimePrecision(q); !strings.Contains(got, pad) {
					t.Errorf("RewriteDatetimePrecision damaged the surrounding text: %q", got)
				}
			}
		})
	}
}
