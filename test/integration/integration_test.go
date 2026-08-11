//go:build integration

// Package integration runs the real proxy binary against real MySQL servers in
// Docker, each with a real pre-4.1 ("old password") account — the situation the
// proxy exists for.
//
//	make test-integration
//	go test -tags integration -v -timeout 30m ./test/integration/...
//
// The whole suite runs against two server images, because they ask for the old
// password in two different ways:
//
//   - mysql:5.5 has pluggable authentication and sends a full
//     AuthSwitchRequest naming mysql_old_password.
//   - mysql:5.6 is the newest server that still implements the plugin at all;
//     5.7 removed it.
//
// The oldest servers (4.1 to 5.1, which is what such a box usually is) instead
// send a bare 0xFE, and publish no official image. That path is covered by the
// MySQL 5.0-shaped fake backend in test/unit.
//
// Clients are exercised three ways: a raw protocol client built on the proxy's
// own packet helpers — so prepared statements and split packets can be driven
// precisely — and the stock mysql 5.6, mysql 8.0 and mariadb clients in
// containers.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ralforion/mysql-old-password-proxy/internal/mysqlwire"
	"github.com/ralforion/mysql-old-password-proxy/internal/relay"
)

// Server images to run the whole suite against.
var serverImages = []string{"mysql:5.6", "mysql:5.5"}

// Client images used to prove stock clients work through the proxy. The 8.0
// client defaults to caching_sha2_password, so it exercises the auth switch;
// mariadb is another driver family entirely.
var clientImages = []struct{ name, image, binary string }{
	{"mysql-5.6", "mysql:5.6", "mysql"},
	{"mysql-8.0", "mysql:8.0", "mysql"},
	{"mariadb-10.11", "mariadb:10.11", "mariadb"},
}

const (
	rootPass = "rootpw"
	// The legacy account, stored as a 16-byte pre-4.1 hash.
	legacyUser = "legacyacct"
	legacyPass = "legacypw"
	// The proxy-local credentials a client presents. Deliberately unrelated to
	// the legacy ones — that separation is half the point.
	frontUser = "appuser"
	frontPass = "frontendpw"

	testDB = "relaytest"
)

// env is one running combination: a MySQL container and a proxy pointed at it.
type env struct {
	t         *testing.T
	image     string
	container string
	mysqlPort int
	relayPort int
	cmd       *exec.Cmd
	log       *lockedBuffer
}

func TestProxy(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	binary := buildProxy(t)
	pullImages(t)

	for _, image := range serverImages {
		t.Run(strings.NewReplacer(":", "-", ".", "-").Replace(image), func(t *testing.T) {
			e := startEnv(t, image, binary)

			// Ordinary use, through stock clients and the raw client.
			t.Run("StockClients", e.testStockClients)
			t.Run("Credentials", e.testCredentials)
			t.Run("UTF8MB4Rewrite", e.testUTF8MB4Rewrite)
			t.Run("NonASCIIRoundTrip", e.testNonASCIIRoundTrip)
			t.Run("TextQuery", e.testTextQuery)
			t.Run("NoSchema", e.testNoSchema)
			t.Run("ErrorsPassThrough", e.testErrorsPassThrough)
			t.Run("LargeResultSet", e.testLargeResultSet)
			t.Run("SplitPacket", e.testSplitPacket)
			t.Run("PreparedStatement", e.testPreparedStatement)
			t.Run("Quit", e.testQuit)
			t.Run("DangerousCapabilityIgnored", e.testDangerousCapabilityIgnored)
			t.Run("ConcurrentSessions", e.testConcurrentSessions)

			// Destructive: these stop or restart the container, so they run last.
			t.Run("ModernClientFailsDirectly", e.testModernClientFailsDirectly)
			t.Run("BackendOutage", e.testBackendOutage)
		})
	}
}

// ------------------------------------------------------------------ harness ---

func buildProxy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "proxy")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	return binary
}

func startEnv(t *testing.T, image, binary string) *env {
	t.Helper()
	e := &env{
		t:         t,
		image:     image,
		container: "mopp-it-" + strings.NewReplacer(":", "-", ".", "-").Replace(image),
	}
	e.startMySQL()
	e.startProxy(binary)
	return e
}

func (e *env) startMySQL() {
	t := e.t
	t.Helper()
	exec.Command("docker", "rm", "-f", e.container).Run()

	e.mysqlPort = freePort(t)
	// --skip-secure-auth is what lets a pre-4.1 account log in at all; these
	// servers refuse old-password logins otherwise. max_allowed_packet is
	// raised so the split-packet test can send a statement over 16 MB.
	out, err := exec.Command("docker", "run", "-d",
		"--name", e.container,
		"--platform", "linux/amd64",
		"-e", "MYSQL_ROOT_PASSWORD="+rootPass,
		"-p", fmt.Sprintf("127.0.0.1:%d:3306", e.mysqlPort),
		e.image,
		"--skip-secure-auth",
		"--max-allowed-packet=64M",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run %s: %v: %s", e.image, err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", e.container).Run() })

	e.waitForMySQL(5 * time.Minute)

	setup := fmt.Sprintf(`
		CREATE DATABASE %[1]s;
		CREATE TABLE %[1]s.widgets (
			id INT PRIMARY KEY,
			name VARCHAR(64) NOT NULL,
			note TEXT
		) ENGINE=InnoDB DEFAULT CHARSET=utf8;
		INSERT INTO %[1]s.widgets VALUES
			(1,'first','Grüße'), (2,'second',NULL), (3,'third','日本語');
		CREATE TABLE %[1]s.wide (id INT PRIMARY KEY AUTO_INCREMENT, payload VARCHAR(255))
			ENGINE=InnoDB DEFAULT CHARSET=utf8;
		INSERT INTO %[1]s.wide (payload) SELECT REPEAT('x',200) FROM
			(SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5
			 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION SELECT 10) a,
			(SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5
			 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION SELECT 10) b,
			(SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5
			 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION SELECT 10) c;

		-- Create the pre-4.1 account. CREATE USER ... IDENTIFIED BY is not
		-- usable here: under old_passwords=1 MySQL 5.6 refuses it outright
		-- ("the password hash doesn't have the expected format"), because the
		-- account still carries the mysql_native_password plugin. Writing the
		-- 16-byte OLD_PASSWORD() hash and the plugin name straight into
		-- mysql.user is what actually produces a legacy account on both 5.5
		-- and 5.6.
		CREATE USER '%[2]s'@'%%';
		GRANT ALL ON %[1]s.* TO '%[2]s'@'%%';
		UPDATE mysql.user
		   SET password = OLD_PASSWORD('%[3]s'), plugin = 'mysql_old_password'
		 WHERE user = '%[2]s';
		FLUSH PRIVILEGES;
	`, testDB, legacyUser, legacyPass)
	if out, err := e.mysql(setup); err != nil {
		t.Fatalf("seed: %v: %s", err, out)
	}

	// The whole exercise is pointless if the account is not actually pre-4.1:
	// a 16-character hash is the old format, 41 the new one.
	got, err := e.mysql(fmt.Sprintf(
		"SELECT LENGTH(password) FROM mysql.user WHERE user='%s'", legacyUser))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != "16" {
		t.Fatalf("the %q account is not stored as a pre-4.1 hash (password length %q)", legacyUser, got)
	}
}

func (e *env) waitForMySQL(timeout time.Duration) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if out, err := e.mysql("SELECT 1"); err == nil && strings.TrimSpace(out) == "1" {
			return
		}
		time.Sleep(2 * time.Second)
	}
	logs, _ := exec.Command("docker", "logs", "--tail", "40", e.container).CombinedOutput()
	e.t.Fatalf("%s never became ready\n%s", e.image, logs)
}

// mysql runs SQL as root inside the container.
func (e *env) mysql(sql string) (string, error) {
	out, err := exec.Command("docker", "exec", "-i", e.container,
		"mysql", "-uroot", "-p"+rootPass, "--default-character-set=utf8",
		"-N", "-B", "-e", sql).CombinedOutput()
	s := stripWarnings(string(out))
	if err != nil {
		return s, fmt.Errorf("%v: %s", err, s)
	}
	return s, nil
}

func (e *env) startProxy(binary string, extraArgs ...string) {
	t := e.t
	t.Helper()
	e.relayPort = freePort(t)

	args := append([]string{
		"-listen", fmt.Sprintf(":%d", e.relayPort),
		"-health-addr", "",
		"-backend", fmt.Sprintf("127.0.0.1:%d", e.mysqlPort),
		"-backend-user", legacyUser,
		"-frontend-user", frontUser,
		"-dial-timeout", "5s",
	}, extraArgs...)

	e.log = &lockedBuffer{}
	e.cmd = exec.Command(binary, args...)
	e.cmd.Env = append(os.Environ(),
		"MYSQL_RELAY_BACKEND_PASSWORD="+legacyPass,
		"MYSQL_RELAY_FRONTEND_PASSWORD="+frontPass,
	)
	e.cmd.Stdout = e.log
	e.cmd.Stderr = e.log
	if err := e.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.cmd.Process.Kill()
		e.cmd.Wait()
		if t.Failed() {
			t.Logf("proxy log for %s:\n%s", e.image, e.log.String())
		}
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", e.addr(), time.Second)
		if err == nil {
			c.Close()
			// Let the startup probe land, so the first test takes the ordinary
			// path rather than the (equally valid) probe-on-demand one.
			e.waitForProbe(20 * time.Second)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the proxy never started listening\n%s", e.log.String())
}

func (e *env) waitForProbe(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(e.log.String(), "backend probe ok") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *env) addr() string { return fmt.Sprintf("127.0.0.1:%d", e.relayPort) }

// clientRun runs a stock client from an image against the proxy.
//
// stdout and stderr are kept apart deliberately. Query results come back on
// stdout, while docker writes image-pull progress and the client writes its
// warnings and errors to stderr — so combining them makes a result comparison
// depend on whether the image happened to be cached, which is the difference
// between a warm laptop and a cold CI runner.
func (e *env) clientRun(t *testing.T, image, binary, user, pass, db, sql string) (stdout, stderr string, err error) {
	t.Helper()
	args := []string{"run", "--rm", "--platform", "linux/amd64",
		"--add-host", "host.docker.internal:host-gateway", image, binary,
		"-h", "host.docker.internal",
		"-P", strconv.Itoa(e.relayPort),
		"--protocol", "TCP",
		"-u", user, "-p" + pass, "-N", "-B", "-e", sql,
	}
	if db != "" {
		args = append(args, db)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var outBuf, errBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return stripWarnings(outBuf.String()), stripWarnings(errBuf.String()), err
}

// pullImages fetches every image the suite uses, before anything is timed or
// compared. Failures are not fatal: the individual docker run would pull it
// anyway, and this is only here to keep the first use of an image cheap.
func pullImages(t *testing.T) {
	t.Helper()
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for _, image := range serverImages {
		seen[image] = true
	}
	for _, c := range clientImages {
		seen[c.image] = true
	}
	for image := range seen {
		wg.Add(1)
		go func(image string) {
			defer wg.Done()
			if out, err := exec.Command("docker", "pull", "--platform", "linux/amd64", image).CombinedOutput(); err != nil {
				t.Logf("pre-pull %s: %v: %s", image, err, out)
			}
		}(image)
	}
	wg.Wait()
}

func stripWarnings(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(line, "Warning: Using a password"),
			strings.HasPrefix(line, "mysql: [Warning]"),
			strings.HasPrefix(line, "mariadb: [Warning]"),
			strings.HasPrefix(line, "WARNING: The requested image"):
			continue
		}
		keep = append(keep, line)
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
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

// ------------------------------------------------- stock clients via docker ---

func (e *env) testStockClients(t *testing.T) {
	for _, c := range clientImages {
		t.Run(c.name, func(t *testing.T) {
			out, errOut, err := e.clientRun(t, c.image, c.binary, frontUser, frontPass, testDB,
				"SELECT id, name FROM widgets ORDER BY id")
			if err != nil {
				t.Fatalf("query through the proxy failed: %v\n%s", err, errOut)
			}
			if want := "1\tfirst\n2\tsecond\n3\tthird"; out != want {
				t.Errorf("got:\n%s\nwant:\n%s", out, want)
			}
		})
	}
}

func (e *env) testCredentials(t *testing.T) {
	cases := []struct{ name, user, pass string }{
		{"wrong password", frontUser, "not-the-password"},
		{"unknown user", "someone-else", frontPass},
		// The legacy credentials must not open the proxy: the two sets are
		// independent, so rotating one does not touch the other.
		{"legacy credentials", legacyUser, legacyPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, err := e.clientRun(t, "mysql:5.6", "mysql", tc.user, tc.pass, testDB, "SELECT 1")
			if err == nil {
				t.Fatalf("the proxy accepted %s: %s", tc.name, out)
			}
			// The client writes its rejection to stderr.
			if !strings.Contains(errOut, "Access denied") {
				t.Errorf("want an Access denied error, got: %s", errOut)
			}
		})
	}
}

// testUTF8MB4Rewrite proves the rewrite fires: the client asks for utf8mb4 and
// the session the legacy server actually sees is utf8.
func (e *env) testUTF8MB4Rewrite(t *testing.T) {
	out, errOut, err := e.clientRun(t, "mysql:5.6", "mysql", frontUser, frontPass, testDB,
		"SET NAMES utf8mb4; SELECT @@session.character_set_client")
	if err != nil {
		t.Fatalf("SET NAMES utf8mb4 failed through the proxy: %v\n%s", err, errOut)
	}
	if out != "utf8" {
		t.Errorf("character_set_client = %q, want utf8 (the rewrite did not fire)", out)
	}
}

// testNonASCIIRoundTrip guards the rewrite against mangling real data.
func (e *env) testNonASCIIRoundTrip(t *testing.T) {
	out, errOut, err := e.clientRun(t, "mysql:5.6", "mysql", frontUser, frontPass, testDB,
		"SET NAMES utf8mb4; SELECT note FROM widgets WHERE id IN (1,3) ORDER BY id")
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if want := "Grüße\n日本語"; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// testModernClientFailsDirectly documents why the proxy exists: a modern client
// cannot authenticate against the pre-4.1 account at all when it goes straight
// to the server. If this ever starts passing, the proxy is obsolete.
func (e *env) testModernClientFailsDirectly(t *testing.T) {
	out, err := exec.Command("docker", "run", "--rm", "--platform", "linux/amd64",
		"--add-host", "host.docker.internal:host-gateway", "mysql:8.0",
		"mysql", "-h", "host.docker.internal", "-P", strconv.Itoa(e.mysqlPort),
		"--protocol", "TCP", "-u", legacyUser, "-p"+legacyPass, "-N", "-B",
		"-e", "SELECT 1").CombinedOutput()
	if err == nil {
		t.Fatalf("a MySQL 8.0 client authenticated directly against the pre-4.1 account; "+
			"the premise of this proxy no longer holds: %s", out)
	}
	t.Logf("expected direct failure: %s", stripWarnings(string(out)))
}

// --------------------------------------------------- raw protocol client ---

// rawClient speaks the client half of the protocol directly, so tests can drive
// exchanges no CLI exposes.
type rawClient struct {
	conn net.Conn
	r    *bufio.Reader
	caps uint32
}

func (e *env) dial(t *testing.T, db string, extraCaps uint32) (*rawClient, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", e.addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(120 * time.Second))

	c := &rawClient{conn: conn, r: bufio.NewReader(conn)}
	greeting, _, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	serverCaps, scramble, err := mysqlwire.ParseServerHandshake(greeting)
	if err != nil {
		t.Fatalf("parse greeting: %v", err)
	}
	if serverCaps&mysqlwire.CapDeprecateEOF != 0 {
		t.Fatal("the proxy offered CLIENT_DEPRECATE_EOF, which it must never do")
	}
	if serverCaps&mysqlwire.CapSSL != 0 {
		t.Fatal("the proxy offered CLIENT_SSL, which it does not implement")
	}

	c.caps = (serverCaps & relay.FramingSafe) | mysqlwire.CapProtocol41 |
		mysqlwire.CapSecureConnection | extraCaps
	if db == "" {
		c.caps &^= mysqlwire.CapConnectWithDB
	}
	resp := mysqlwire.BuildHandshakeResponse41(c.caps, 45, frontUser,
		mysqlwire.NativePassword(scramble, frontPass), db, "")
	if err := mysqlwire.WritePacket(conn, resp, 1); err != nil {
		t.Fatalf("write handshake response: %v", err)
	}
	p, _, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	return c, p
}

func (e *env) mustDial(t *testing.T, db string) *rawClient {
	t.Helper()
	c, p := e.dial(t, db, 0)
	if !mysqlwire.IsOK(p) {
		t.Fatalf("login failed: %s", mysqlwire.ErrText(p))
	}
	return c
}

func (c *rawClient) send(t *testing.T, payload []byte) {
	t.Helper()
	if err := mysqlwire.WritePacket(c.conn, payload, 0); err != nil {
		t.Fatalf("write command: %v", err)
	}
}

type resultSet struct {
	columns int
	rows    [][]byte
	ok      bool
	errText string
}

func (c *rawClient) query(t *testing.T, sql string) resultSet {
	t.Helper()
	c.send(t, append([]byte{mysqlwire.ComQuery}, sql...))
	return c.readResultSet(t, sql)
}

// readResultSet parses a response the way a client without
// CLIENT_DEPRECATE_EOF must: column count, column definitions, EOF, rows, EOF.
// If the proxy ever corrupted framing, this is where it would show up.
func (c *rawClient) readResultSet(t *testing.T, what string) resultSet {
	t.Helper()
	first, _, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("%s: read response: %v", what, err)
	}
	switch {
	case len(first) == 0:
		t.Fatalf("%s: empty response packet", what)
	case mysqlwire.IsOK(first):
		return resultSet{ok: true}
	case mysqlwire.IsErr(first):
		return resultSet{errText: mysqlwire.ErrText(first)}
	}

	n, adv := mysqlwire.LenencInt(first)
	if adv == 0 || n == 0 {
		t.Fatalf("%s: bad column count packet %x", what, first)
	}
	rs := resultSet{columns: int(n)}
	for i := 0; i < rs.columns; i++ {
		if _, _, err := mysqlwire.ReadPacket(c.r); err != nil {
			t.Fatalf("%s: read column definition %d: %v", what, i, err)
		}
	}
	if p, _, err := mysqlwire.ReadPacket(c.r); err != nil {
		t.Fatalf("%s: read column EOF: %v", what, err)
	} else if !mysqlwire.IsEOF(p) {
		t.Fatalf("%s: expected EOF after the column definitions, got %x — framing is out of step", what, p)
	}
	for {
		p, _, err := mysqlwire.ReadPacket(c.r)
		if err != nil {
			t.Fatalf("%s: read row: %v", what, err)
		}
		if mysqlwire.IsEOF(p) {
			return rs
		}
		if mysqlwire.IsErr(p) {
			rs.errText = mysqlwire.ErrText(p)
			return rs
		}
		rs.rows = append(rs.rows, p)
	}
}

func (e *env) testTextQuery(t *testing.T) {
	c := e.mustDial(t, testDB)

	rs := c.query(t, "SELECT id, name, note FROM widgets ORDER BY id")
	if rs.errText != "" {
		t.Fatalf("query error: %s", rs.errText)
	}
	if rs.columns != 3 {
		t.Errorf("columns = %d, want 3", rs.columns)
	}
	if len(rs.rows) != 3 {
		t.Errorf("rows = %d, want 3", len(rs.rows))
	}

	// The session must be attached to the schema requested in the handshake.
	rs = c.query(t, "SELECT DATABASE()")
	if len(rs.rows) != 1 || !bytes.Contains(rs.rows[0], []byte(testDB)) {
		t.Errorf("SELECT DATABASE() = %q, want %s (the handshake schema was dropped)", rs.rows, testDB)
	}
	// And it must really be the legacy account on the far side.
	rs = c.query(t, "SELECT SUBSTRING_INDEX(CURRENT_USER(),'@',1)")
	if len(rs.rows) != 1 || !bytes.Contains(rs.rows[0], []byte(legacyUser)) {
		t.Errorf("CURRENT_USER() = %q, want the %s account", rs.rows, legacyUser)
	}
}

func (e *env) testNoSchema(t *testing.T) {
	c := e.mustDial(t, "")
	if rs := c.query(t, "SELECT 1"); rs.errText != "" || len(rs.rows) != 1 {
		t.Fatalf("a query without a default schema failed: %+v", rs)
	}
}

func (e *env) testErrorsPassThrough(t *testing.T) {
	c := e.mustDial(t, testDB)
	rs := c.query(t, "SELECT * FROM no_such_table")
	if rs.errText == "" {
		t.Fatal("a failing statement produced no error packet")
	}
	if !strings.Contains(rs.errText, "no_such_table") {
		t.Errorf("error text = %q, want it to name the table", rs.errText)
	}
	// The session must survive an error.
	if rs := c.query(t, "SELECT 1"); rs.errText != "" || len(rs.rows) != 1 {
		t.Errorf("the session did not survive an error: %+v", rs)
	}
}

// testLargeResultSet walks a result set big enough to cross many packets, plus
// an aggregate and a join, per the test plan.
func (e *env) testLargeResultSet(t *testing.T) {
	c := e.mustDial(t, testDB)

	rs := c.query(t, "SELECT id, payload FROM wide ORDER BY id")
	if rs.errText != "" {
		t.Fatalf("query error: %s", rs.errText)
	}
	if len(rs.rows) != 1000 {
		t.Errorf("rows = %d, want 1000", len(rs.rows))
	}
	if rs := c.query(t, "SELECT COUNT(*), SUM(id) FROM wide"); len(rs.rows) != 1 {
		t.Errorf("the aggregate returned %d rows, want 1", len(rs.rows))
	}
	rs = c.query(t, "SELECT w.id, x.name FROM wide w JOIN widgets x ON x.id = w.id ORDER BY w.id")
	if rs.errText != "" || len(rs.rows) != 3 {
		t.Errorf("the join returned %d rows (%s), want 3", len(rs.rows), rs.errText)
	}
}

// testSplitPacket sends a statement larger than 16 MB, which the protocol
// carries as a full 0xFFFFFF packet followed by a continuation. The
// continuation must be forwarded untouched, and in particular must not be
// mistaken for a new command.
func (e *env) testSplitPacket(t *testing.T) {
	c := e.mustDial(t, testDB)

	const literal = mysqlwire.MaxPayload + 1024
	sql := "SELECT LENGTH('" + strings.Repeat("y", literal) + "')"
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
		t.Fatalf("write the final chunk: %v", err)
	}

	rs := c.readResultSet(t, "split packet")
	if rs.errText != "" {
		t.Fatalf("the split-packet query failed: %s", rs.errText)
	}
	if len(rs.rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rs.rows))
	}
	if want := strconv.Itoa(literal); !bytes.Contains(rs.rows[0], []byte(want)) {
		t.Errorf("row = %q, want it to contain %s", rs.rows[0], want)
	}
}

// testPreparedStatement drives COM_STMT_PREPARE / EXECUTE / CLOSE. The binary
// protocol frames results differently from the text protocol, so it has to be
// tested rather than assumed to pass through.
func (e *env) testPreparedStatement(t *testing.T) {
	const (
		comStmtPrepare = 0x16
		comStmtExecute = 0x17
		comStmtClose   = 0x19
	)
	c := e.mustDial(t, testDB)

	c.send(t, append([]byte{comStmtPrepare}, "SELECT id, name FROM widgets WHERE id > ? ORDER BY id"...))
	p, _, err := mysqlwire.ReadPacket(c.r)
	if err != nil {
		t.Fatalf("read the prepare response: %v", err)
	}
	if mysqlwire.IsErr(p) {
		t.Fatalf("prepare failed: %s", mysqlwire.ErrText(p))
	}
	if len(p) < 12 {
		t.Fatalf("the prepare-OK is %d bytes, want at least 12", len(p))
	}
	stmtID := []byte{p[1], p[2], p[3], p[4]}
	numColumns := int(p[5]) | int(p[6])<<8
	numParams := int(p[7]) | int(p[8])<<8
	if numColumns != 2 || numParams != 1 {
		t.Fatalf("the prepare-OK reports %d columns and %d parameters, want 2 and 1", numColumns, numParams)
	}
	// Parameter definitions then EOF, column definitions then EOF.
	for _, n := range []int{numParams, numColumns} {
		for i := 0; i < n; i++ {
			if _, _, err := mysqlwire.ReadPacket(c.r); err != nil {
				t.Fatalf("read a definition packet: %v", err)
			}
		}
		if p, _, err := mysqlwire.ReadPacket(c.r); err != nil {
			t.Fatalf("read the definition EOF: %v", err)
		} else if !mysqlwire.IsEOF(p) {
			t.Fatalf("expected EOF after the definitions, got %x", p)
		}
	}

	// EXECUTE with one bound BIGINT parameter: id > 1.
	req := []byte{comStmtExecute}
	req = append(req, stmtID...)
	req = append(req, 0x00)                   // flags: CURSOR_TYPE_NO_CURSOR
	req = append(req, 0x01, 0, 0, 0)          // iteration count
	req = append(req, 0x00)                   // NULL bitmap for one parameter
	req = append(req, 0x01)                   // new-parameters-bound flag
	req = append(req, 0x08, 0x00)             // MYSQL_TYPE_LONGLONG, signed
	req = append(req, 1, 0, 0, 0, 0, 0, 0, 0) // the value
	c.send(t, req)

	rs := c.readResultSet(t, "COM_STMT_EXECUTE")
	if rs.errText != "" {
		t.Fatalf("execute failed: %s", rs.errText)
	}
	if rs.columns != 2 {
		t.Errorf("columns = %d, want 2", rs.columns)
	}
	if len(rs.rows) != 2 {
		t.Errorf("binary rows = %d, want 2 (ids 2 and 3)", len(rs.rows))
	}
	// Binary rows start with 0x00 and a NULL bitmap, unlike text rows.
	for i, row := range rs.rows {
		if len(row) == 0 || row[0] != 0x00 {
			t.Errorf("row %d does not look like a binary-protocol row: %x", i, row)
		}
	}

	c.send(t, append([]byte{comStmtClose}, stmtID...))
	// COM_STMT_CLOSE has no response; the session must still work.
	if rs := c.query(t, "SELECT 1"); rs.errText != "" || len(rs.rows) != 1 {
		t.Errorf("the session broke after COM_STMT_CLOSE: %+v", rs)
	}
}

func (e *env) testQuit(t *testing.T) {
	c := e.mustDial(t, testDB)
	c.send(t, []byte{mysqlwire.ComQuit})
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := mysqlwire.ReadPacket(c.r); err == nil {
		t.Error("the proxy kept the connection open after COM_QUIT")
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Logf("close reported as %v (acceptable)", err)
	}
}

// testDangerousCapabilityIgnored covers what a real MySQL server does with
// capabilities it never advertised: ignore them. Stock clients send
// CLIENT_DEPRECATE_EOF and friends unconditionally, so refusing them would
// break every mysql 8.0 client. What matters is that the framing stays the one
// the proxy offered — EOF-terminated result sets — which readResultSet checks
// on every row.
func (e *env) testDangerousCapabilityIgnored(t *testing.T) {
	c, p := e.dial(t, testDB, mysqlwire.CapDeprecateEOF|mysqlwire.CapSessionTrack|mysqlwire.CapQueryAttributes)
	if !mysqlwire.IsOK(p) {
		t.Fatalf("login refused: %s", mysqlwire.ErrText(p))
	}
	rs := c.query(t, "SELECT id, name FROM widgets ORDER BY id")
	if rs.errText != "" {
		t.Fatalf("query error: %s", rs.errText)
	}
	if len(rs.rows) != 3 {
		t.Errorf("rows = %d, want 3 — result-set framing did not stay EOF-terminated", len(rs.rows))
	}
}

func (e *env) testConcurrentSessions(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := e.mustDial(t, testDB)
			for n := 0; n < 3; n++ {
				sql := fmt.Sprintf("SELECT %d", i)
				rs := c.query(t, sql)
				if rs.errText != "" || len(rs.rows) != 1 {
					t.Errorf("session %d: %+v", i, rs)
					return
				}
				if !bytes.Contains(rs.rows[0], []byte(strconv.Itoa(i))) {
					t.Errorf("session %d got the wrong row: %q", i, rs.rows[0])
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// testBackendOutage covers the failure mode from the test plan: with the legacy
// server gone, a client must get an error rather than hang.
func (e *env) testBackendOutage(t *testing.T) {
	if out, err := exec.Command("docker", "stop", e.container).CombinedOutput(); err != nil {
		t.Fatalf("docker stop: %v: %s", err, out)
	}
	defer func() {
		if out, err := exec.Command("docker", "start", e.container).CombinedOutput(); err != nil {
			t.Fatalf("docker start: %v: %s", err, out)
		}
		e.waitForMySQL(2 * time.Minute)
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, p := e.dial(t, testDB, 0)
		if !mysqlwire.IsErr(p) {
			t.Errorf("with the backend down the proxy answered %x, want an error packet", p)
			return
		}
		if !strings.Contains(mysqlwire.ErrText(p), "could not reach the legacy server") {
			t.Errorf("error text = %q", mysqlwire.ErrText(p))
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the proxy hung instead of reporting that the backend is down")
	}

	// And it must recover once the server comes back.
	exec.Command("docker", "start", e.container).Run()
	e.waitForMySQL(2 * time.Minute)
	c := e.mustDial(t, testDB)
	if rs := c.query(t, "SELECT 1"); rs.errText != "" || len(rs.rows) != 1 {
		t.Errorf("the proxy did not recover after the backend came back: %+v", rs)
	}
}
