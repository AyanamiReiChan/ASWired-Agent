package speedtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDownloadBudgetSharedAcrossWorkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, 128<<10)) }))
	defer server.Close()
	for _, parallel := range []int{1, 8, 16, 32, 64} {
		bytes, elapsed, failures := downloadMeasurement(context.Background(), server.Client(), server.URL, 5, parallel, 1<<20)
		if bytes != 1<<20 || elapsed <= 0 || failures != 0 {
			t.Fatalf("parallel=%d bytes=%d failures=%d", parallel, bytes, failures)
		}
	}
}
func TestEmptyAndFailedResponsesDoNotLoop(t *testing.T) {
	for _, status := range []int{200, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		bytes, elapsed, failures := downloadMeasurement(context.Background(), server.Client(), server.URL, 5, 8, 1<<20)
		server.Close()
		if bytes != 0 || elapsed >= 4 || failures != 8 {
			t.Fatalf("empty/error response not bounded: %d %f %d", bytes, elapsed, failures)
		}
	}
}
