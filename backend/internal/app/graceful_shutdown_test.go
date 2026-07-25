package app

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/health"
	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/wkdpublish"
)

// freeTCPPort asks the OS for a currently-unused TCP port by briefly binding
// to port 0 and reading back what it was assigned. WEB_PORT can't just be set
// to "0" for this: config.EnvInt treats 0 as "unset" and falls back to the
// hardcoded production default (5866), which risks colliding with a real
// instance or another test.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find a free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// newGracefulShutdownTestDeps builds a minimal runDeps good enough to start
// runServer/runAll and shut them down again, entirely inside temp
// directories.
func newGracefulShutdownTestDeps(t *testing.T) runDeps {
	t.Helper()

	t.Setenv("WEB_PORT", strconv.Itoa(freeTCPPort(t)))
	t.Setenv("CONFIG_DIR", t.TempDir())
	t.Setenv("STATE_DIR", t.TempDir())
	t.Setenv("LOG_DIR", t.TempDir())

	stateDir := t.TempDir()
	store, err := state.New(stateDir)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	// Mirrors Run()'s real wiring: one wkdStore, shared by both the poller
	// and the api server in runAll (see R3/wkdpublish.Store's doc comment).
	wkdStore, err := wkdpublish.New(stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}

	return runDeps{
		cfg:        config.Default(),
		configPath: filepath.Join(t.TempDir(), "config.yaml"),
		configDir:  t.TempDir(),
		stateDir:   stateDir,
		logger:     newTestLogger(t),
		store:      store,
		users:      newTestUsersStore(t),
		health:     health.NewService(),
		wkdStore:   wkdStore,
	}
}

// TestRunServer_ShutsDownGracefullyOnSIGTERM proves runServer (which
// previously had zero signal handling and would just be killed mid-request
// by SIGTERM) now: (1) actually installs a signal handler, (2) returns
// promptly once SIGTERM arrives, and (3) does so without panicking — which
// is only possible because Prepare constructs the *http.Server before the
// Serve goroutine races with the (near-immediate) signal below.
func TestRunServer_ShutsDownGracefullyOnSIGTERM(t *testing.T) {
	d := newGracefulShutdownTestDeps(t)

	result := make(chan error, 1)
	go func() {
		result <- runServer(d)
	}()

	// Send the signal essentially immediately, well before we can be sure
	// the Serve goroutine has actually started listening — this is exactly
	// the race Task 20 closes via eager Prepare().
	time.Sleep(10 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to self: %v", err)
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runServer returned an error after SIGTERM: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runServer did not return after SIGTERM — no signal handling, or shutdown hung")
	}
}

// TestRunAll_ShutsDownGracefullyOnSIGTERM proves runAll's stop signal now
// also tears down the HTTP server (not just the poller, as before Task 20),
// and does so without panicking or hanging even when the signal arrives
// almost immediately after startup.
func TestRunAll_ShutsDownGracefullyOnSIGTERM(t *testing.T) {
	d := newGracefulShutdownTestDeps(t)

	result := make(chan error, 1)
	go func() {
		result <- runAll(d)
	}()

	time.Sleep(20 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to self: %v", err)
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runAll returned an error after SIGTERM: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runAll did not return after SIGTERM — shutdown did not complete")
	}
}
