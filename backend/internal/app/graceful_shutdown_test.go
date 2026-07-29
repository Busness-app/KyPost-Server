package app

import (
	"context"
	"net"
	"os"
	"os/signal"
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
	// SECRET_DIR must be set too. Without it config.Paths falls back to the
	// production default (/kypost/private), and api.NewServer then tries to
	// mkdir /kypost on whatever host is running the tests — which fails on CI
	// and, far worse, would succeed as root.
	t.Setenv("SECRET_DIR", t.TempDir())

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

// These tests cancel a context rather than sending a signal. An earlier
// version called syscall.Kill(os.Getpid(), SIGTERM) and slept 10ms first,
// betting that runServer had reached its signal.Notify by then. It had not:
// api.NewServer, Prepare and eight sweeper goroutines all ran ahead of the
// registration, so SIGTERM kept its default disposition and killed the test
// binary outright ("signal: terminated", no test output). Signal registration
// is process-global state and does not belong in a unit test; Run() now owns
// it via signal.NotifyContext and the run functions observe only a context,
// which is what these drive.

// TestRunServer_ShutsDownGracefullyOnCancel proves runServer returns promptly
// and without panicking when its context is cancelled, even if the
// cancellation lands before the Serve goroutine has started listening — the
// race that eager Prepare() exists to close.
func TestRunServer_ShutsDownGracefullyOnCancel(t *testing.T) {
	d := newGracefulShutdownTestDeps(t)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runServer(ctx, d)
	}()

	// Cancel immediately. Unlike a sleep-then-signal, this is safe to do
	// before runServer has made any progress at all: an already-cancelled
	// context is observed by the select whenever it gets there.
	cancel()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runServer returned an error after cancellation: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runServer did not return after cancellation — shutdown hung")
	}
}

// TestRunAll_ShutsDownGracefullyOnCancel proves runAll's stop path tears down
// the HTTP server as well as the poller, without panicking or hanging when
// cancellation arrives immediately after startup.
func TestRunAll_ShutsDownGracefullyOnCancel(t *testing.T) {
	d := newGracefulShutdownTestDeps(t)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runAll(ctx, d)
	}()

	cancel()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runAll returned an error after cancellation: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runAll did not return after cancellation — shutdown did not complete")
	}
}

// TestRun_InstallsSignalHandlingBeforeBuildingAnyServer is the regression
// guard for what actually broke: the window between process start and signal
// registration. It asserts on Run's structure via the only thing observable
// from a test — that a SIGTERM delivered to this process after Run has
// installed its handler is absorbed rather than fatal. Kept separate from the
// shutdown tests above so a failure here is unambiguous.
func TestRun_InstallsSignalHandlingBeforeBuildingAnyServer(t *testing.T) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to self: %v", err)
	}

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("signal.NotifyContext did not observe SIGTERM")
	}
}
