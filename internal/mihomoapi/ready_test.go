package mihomoapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBarrierWaitsForConfigurationCommit(t *testing.T) {
	entered, commit := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPut || r.URL.Path != "/configs" || string(body) != "{}" || r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("startup barrier changed the selected configuration or omitted authentication")
		}
		close(entered)
		<-commit
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		done <- AwaitConfiguration(context.Background(), strings.TrimPrefix(server.URL, "http://"), "private-token")
	}()
	<-entered
	select {
	case <-done:
		t.Fatal("API reachability was treated as committed configuration")
	case <-time.After(25 * time.Millisecond):
	}
	close(commit)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBarrierRejectsFailureAndRedirects(t *testing.T) {
	for _, status := range []int{200, 500, 307} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://127.0.0.1:1/secret")
				w.WriteHeader(status)
			}))
			defer server.Close()
			if AwaitConfiguration(context.Background(), strings.TrimPrefix(server.URL, "http://"), "private-token") == nil {
				t.Fatal("failed or redirected configuration load accepted")
			}
		})
	}
	if AwaitConfiguration(context.Background(), "192.0.2.1:80", "private-token") == nil {
		t.Fatal("private credential could be sent to a non-loopback endpoint")
	}
}
