package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestTransientStatus(t *testing.T) {
	transient := []int{429, 500, 502, 503, 504}
	for _, c := range transient {
		if !transientStatus(c) {
			t.Errorf("status %d should be transient", c)
		}
	}
	for _, c := range []int{200, 301, 400, 401, 403, 404} {
		if transientStatus(c) {
			t.Errorf("status %d should NOT be transient", c)
		}
	}
}

func TestGetWithRetry_RetriesThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail with 504 on the first two attempts, then succeed.
		if atomic.AddInt32(&calls, 1) <= 2 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := getWithRetry(context.Background(), srv.URL, map[string]string{"Accept": "test"})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("server hit %d times, want 3", got)
	}
}

func TestGetWithRetry_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: first transient response triggers the ctx-aware wait

	if _, err := getWithRetry(ctx, srv.URL, nil); err == nil {
		t.Fatal("expected error on cancelled context")
	}
}
