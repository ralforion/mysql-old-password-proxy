// Package unit holds the tests that need no network and no Docker.
//
//	go test ./test/unit/...
package unit

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/ralforion/mysql-old-password-proxy/internal/mysqlwire"
)

// TestPWHash pins the pre-4.1 hash against values measured on a real MySQL
// 5.6.51 server: OLD_PASSWORD() prints exactly PWHash's two words as hex.
//
//	docker run --rm mysql:5.6 ... -e "SELECT OLD_PASSWORD('secret')"
func TestPWHash(t *testing.T) {
	// Measured 2026-08-11 against mysql:5.6.51.
	vectors := map[string]string{
		" pass":                "29bad1457ee5e49e",
		"pass ":                "29bad1457ee5e49e", // spaces and tabs are skipped
		"123\t456":             "565491d704013245",
		"C0mpl!ca ted#PASS123": "4b34e7005473714b",
		"secret":               "428567f408994404",
		"legacy":               "7457596f4d12255d",
		"a":                    "60671c896665c3fa",
	}
	for pw, want := range vectors {
		h := mysqlwire.PWHash([]byte(pw))
		if got := fmt.Sprintf("%08x%08x", h[0], h[1]); got != want {
			t.Errorf("PWHash(%q) = %s, want %s", pw, got, want)
		}
	}
}

// TestScrambleOldPassword pins the pre-4.1 scramble. The vectors match
// go-sql-driver/mysql's, and the algorithm is exercised end to end against a
// real old-password account by the integration suite.
func TestScrambleOldPassword(t *testing.T) {
	scramble := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	vectors := []struct{ pass, out string }{
		{" pass", "47575c5a435b4251"},
		{"pass ", "47575c5a435b4251"},
		{"123\t456", "575c47505b5b5559"},
		{"C0mpl!ca ted#PASS123", "5d5d554849584a45"},
	}
	for _, v := range vectors {
		if got := hex.EncodeToString(mysqlwire.ScrambleOldPassword(scramble, v.pass)); got != v.out {
			t.Errorf("ScrambleOldPassword(%q) = %s, want %s", v.pass, got, v.out)
		}
	}
}

func TestScrambleOldPasswordProperties(t *testing.T) {
	if got := mysqlwire.ScrambleOldPassword([]byte("12345678"), ""); got != nil {
		t.Errorf("an empty password should produce no auth response, got %x", got)
	}
	// Only the first 8 bytes of the scramble may take part.
	short := mysqlwire.ScrambleOldPassword([]byte("12345678"), "secret")
	long := mysqlwire.ScrambleOldPassword([]byte("12345678wxyzabcdefgh"), "secret")
	if !bytes.Equal(short, long) {
		t.Errorf("scramble bytes beyond the first 8 changed the result: %x vs %x", short, long)
	}
	if len(short) != 8 {
		t.Errorf("response is %d bytes, want 8", len(short))
	}
	if bytes.Equal(short, mysqlwire.ScrambleOldPassword([]byte("87654321"), "secret")) {
		t.Error("the response does not depend on the scramble")
	}
}

// TestNativePasswordStage2 checks the SHA1(SHA1(pw)) half against MySQL's
// PASSWORD() output, measured on the same 5.6.51 server.
func TestNativePasswordStage2(t *testing.T) {
	vectors := map[string]string{
		"secret": "14E65567ABDB5135D0CFD9A70B3032C179A49EE7",
		"a":      "667F407DE7C6AD07358FA38DAED7828A72014B4E",
	}
	for pw, want := range vectors {
		h1 := sha1.Sum([]byte(pw))
		h2 := sha1.Sum(h1[:])
		if got := strings.ToUpper(hex.EncodeToString(h2[:])); got != want {
			t.Errorf("SHA1(SHA1(%q)) = %s, want %s", pw, got, want)
		}
	}
}

func TestNativePassword(t *testing.T) {
	scramble := []byte("12345678901234567890")
	if got := mysqlwire.NativePassword(scramble, ""); got != nil {
		t.Errorf("an empty password should produce no auth response, got %x", got)
	}
	resp := mysqlwire.NativePassword(scramble, "secret")
	if len(resp) != 20 {
		t.Fatalf("response is %d bytes, want 20", len(resp))
	}

	// resp = SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw)))
	h1 := sha1.Sum([]byte("secret"))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(scramble)
	h.Write(h2[:])
	want := h.Sum(nil)
	for i := range want {
		want[i] ^= h1[i]
	}
	if !bytes.Equal(resp, want) {
		t.Errorf("NativePassword = %x, want %x", resp, want)
	}
	if bytes.Equal(resp, mysqlwire.NativePassword([]byte("09876543210987654321"), "secret")) {
		t.Error("the response does not depend on the scramble")
	}
}

func TestNewScramble(t *testing.T) {
	a, err := mysqlwire.NewScramble()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 20 {
		t.Fatalf("scramble is %d bytes, want 20", len(a))
	}
	// The protocol treats auth-plugin-data as a NUL-terminated string.
	if bytes.IndexByte(a, 0) >= 0 {
		t.Errorf("scramble contains a NUL: %x", a)
	}
	for _, b := range a {
		if b < 33 || b > 126 {
			t.Errorf("scramble byte %d is outside printable ASCII: %x", b, a)
			break
		}
	}
	if b, _ := mysqlwire.NewScramble(); bytes.Equal(a, b) {
		t.Error("two scrambles came out identical")
	}
}
