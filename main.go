// Command mysql-old-password-proxy bridges a modern MySQL client to a legacy
// server that only accepts pre-4.1 ("mysql_old_password") authentication.
//
// # Why this exists
//
// Modern MySQL drivers have dropped pre-4.1 authentication. MariaDB
// Connector/J 3.x removed it, MySQL Connector/J removed it in 8.0, and a client
// meeting a server that still holds a 16-byte password hash fails during
// plugin negotiation with something like:
//
//	Client does not support authentication protocol requested by server.
//	plugin type was = ''
//
// The proper fix is one ALTER USER on the legacy server to store a
// mysql_native_password hash instead. This relay is for when that is not
// available: no DBA access, or a server nobody is allowed to touch. It
// terminates authentication separately on each side — mysql_native_password
// towards its clients, pre-4.1 towards the legacy server — and relays the
// post-authentication packet stream.
//
// The protocol work lives in internal/mysqlwire; the relaying and the
// capability policy that makes it safe live in internal/relay, whose package
// documentation explains the design.
//
// No external dependencies: standard library only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/ralforion/mysql-old-password-proxy/internal/relay"
)

// version is stamped at build time with -ldflags "-X main.version=...", which
// the Makefile and the release workflow both do. Left unset, it falls back to
// the VCS stamp the Go toolchain embeds, so even a plain `go build` produces a
// binary that can say what it is.
var version = ""

func buildVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 12 {
				s.Value = s.Value[:12]
			}
			revision = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				modified = "-dirty"
			}
		}
	}
	if revision == "" {
		return "dev"
	}
	return revision + modified
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	var (
		listenAddr    = flag.String("listen", ":3306", "address to listen on for clients")
		healthAddr    = flag.String("health-addr", ":8081", "address for the HTTP health endpoint (empty disables it)")
		backendAddr   = flag.String("backend", "", "legacy MySQL server host:port (required)")
		backendUser   = flag.String("backend-user", "", "username on the legacy server (required)")
		frontendUsr   = flag.String("frontend-user", "", "username clients must present (defaults to -backend-user)")
		serverVer     = flag.String("server-version", "5.5.62-auth-relay", "version string advertised to clients")
		rewriteMB4    = flag.Bool("rewrite-utf8mb4", true, "rewrite utf8mb4 to utf8 in queries (MySQL 5.0 has no utf8mb4)")
		fakeOKRe      = flag.String("fake-ok-regex", "", "regexp; matching COM_QUERY statements are answered OK without reaching the backend")
		logQueries    = flag.Bool("log-queries", false, "log every COM_QUERY (verbose; may expose data)")
		dialTimeout   = flag.Duration("dial-timeout", 10*time.Second, "timeout for connecting to the backend")
		authTimeout   = flag.Duration("auth-timeout", 30*time.Second, "timeout for completing authentication on either side")
		maxConns      = flag.Int("max-connections", 0, "maximum concurrent client sessions, each holding one backend connection (0 = unlimited)")
		frontFromBack = flag.Bool("frontend-password-from-backend", false,
			"take the client-facing password from MYSQL_RELAY_BACKEND_PASSWORD, so clients authenticate with the legacy server's own password and only one secret has to be deployed")
		shutdownGr  = flag.Duration("shutdown-timeout", 30*time.Second, "how long to wait for in-flight connections on SIGTERM")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	version = buildVersion()
	if *showVersion {
		fmt.Printf("mysql-old-password-proxy %s %s %s/%s\n",
			version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}

	cfg := relay.Config{
		Backend:     *backendAddr,
		BackendUser: *backendUser,
		// Passwords come from the environment, never flags: flags are visible
		// in the process list and in `kubectl describe pod`.
		BackendPass:    os.Getenv("MYSQL_RELAY_BACKEND_PASSWORD"),
		FrontendUser:   *frontendUsr,
		FrontendPass:   os.Getenv("MYSQL_RELAY_FRONTEND_PASSWORD"),
		ServerVersion:  *serverVer,
		RewriteUTF8MB4: *rewriteMB4,
		LogQueries:     *logQueries,
		DialTimeout:    *dialTimeout,
		AuthTimeout:    *authTimeout,
		MaxConnections: *maxConns,
	}
	if *frontFromBack && cfg.FrontendPass == "" {
		// One credential to deploy, at the cost of putting the legacy server's
		// password into every client's configuration. Worth saying out loud in
		// the log, because the password of a server nobody can run ALTER USER
		// on is usually also a password nobody can rotate.
		cfg.FrontendPass = cfg.BackendPass
		log.Print("-frontend-password-from-backend: clients authenticate with the legacy server's own password; " +
			"it will be stored in every client's configuration, and cannot be rotated without changing the legacy server")
	}
	switch {
	case cfg.Backend == "":
		log.Fatal("-backend is required (host:port of the legacy MySQL server)")
	case cfg.BackendUser == "":
		log.Fatal("-backend-user is required")
	case cfg.BackendPass == "":
		log.Fatal("MYSQL_RELAY_BACKEND_PASSWORD is required")
	case cfg.FrontendPass == "":
		log.Fatal("MYSQL_RELAY_FRONTEND_PASSWORD is required (or pass -frontend-password-from-backend to use the legacy one for clients too)")
	}
	if *fakeOKRe != "" {
		re, err := regexp.Compile(*fakeOKRe)
		if err != nil {
			log.Fatalf("-fake-ok-regex: %v", err)
		}
		cfg.FakeOK = re
	}

	srv, err := relay.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	cfg = srv.Config() // defaults applied

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listenAddr, err)
	}
	log.Printf("mysql-old-password-proxy %s listening on %s -> %s (backend user %q, frontend user %q, advertising %q)",
		version, *listenAddr, cfg.Backend, cfg.BackendUser, cfg.FrontendUser, cfg.ServerVersion)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *healthAddr != "" {
		go serveHealth(ctx, *healthAddr, srv)
	}

	// Probe the backend at startup: it validates the credentials in the Secret
	// (so a bad password is loud at boot, not on the first query) and caches
	// the capability flags every client handshake is masked by.
	go srv.ProbeBackendUntilOK(ctx, 30*time.Second)

	go func() {
		<-ctx.Done()
		log.Print("signal received; no longer accepting connections")
		ln.Close()
	}()

	if err := srv.Serve(ln); err != nil {
		log.Printf("serve: %v", err)
	}

	drain, cancel := context.WithTimeout(context.Background(), *shutdownGr)
	defer cancel()
	if srv.Wait(drain) {
		log.Print("all connections closed; exiting")
	} else {
		log.Printf("shutdown timeout after %s with connections still open; exiting", *shutdownGr)
	}
}

// serveHealth exposes liveness for Kubernetes on a port that is not the MySQL
// port, so that probing the relay never opens a connection to the legacy
// server.
//
// It reports healthy even when the legacy server is unreachable: taking the
// pod out of the Service would turn a clear MySQL error into a connection
// refused, which is harder to diagnose from the client.
func serveHealth(ctx context.Context, addr string, srv *relay.Server) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		caps, known := srv.BackendCaps()
		capsText := "unknown (backend not reached yet)"
		if known {
			capsText = fmt.Sprintf("0x%08x", caps)
		}
		fmt.Fprintf(w, "ok\nversion %s\nbackend-caps %s\nconnections %d\n",
			version, capsText, srv.LiveConnections())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h)
	mux.HandleFunc("/readyz", h)

	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("health server: %v", err)
	}
}
