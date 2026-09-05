package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestShutdownDoesNotExtendOrdinaryRequestsForBackups(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }))
	defer srv.Close()
	defer close(release)
	go func() {
		res, err := http.Get(srv.URL)
		if err == nil {
			res.Body.Close()
		}
	}()
	<-entered
	api := &Server{httpServer: srv.Config}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := api.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("ordinary request received backup grace")
	}
	if api.beginBackupRun() {
		api.backupRuns.Done()
		t.Fatal("backup started after drain")
	}
}

func TestShutdownWaitsForBackupCompletionAfterHTTPDeadline(t *testing.T) {
	api := &Server{httpServer: &http.Server{}}
	if !api.beginBackupRun() {
		t.Fatal("backup refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- api.Shutdown(ctx) }()
	select {
	case <-done:
		t.Fatal("shutdown abandoned backup completion audit")
	case <-time.After(30 * time.Millisecond):
	}
	api.backupRuns.Done()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("completed backup did not release shutdown")
	}
}
