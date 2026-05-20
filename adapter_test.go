package breachwatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasswordBreachedMatchesHIBPSuffix(t *testing.T) {
	var sawPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		if r.URL.Path != "/range/5BAA6" {
			t.Fatalf("path = %q, want /range/5BAA6", r.URL.Path)
		}
		if strings.Contains(r.URL.Path, "password") {
			t.Fatalf("raw password leaked in request path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("003D68EB55068C33ACE09247EE4C639306B:2\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n"))
	}))
	defer server.Close()

	checker := NewWithClient(server.URL, server.Client())
	count, err := checker.PasswordBreached(context.Background(), "password")
	if err != nil {
		t.Fatalf("PasswordBreached returned error: %v", err)
	}
	if count != 42 {
		t.Fatalf("count = %d, want 42", count)
	}
	if sawPath == "" {
		t.Fatal("mock HIBP server was not called")
	}
}

func TestPasswordBreachedReturnsZeroWhenSuffixMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:7\r\n"))
	}))
	defer server.Close()

	checker := NewWithClient(server.URL, server.Client())
	count, err := checker.PasswordBreached(context.Background(), "password")
	if err != nil {
		t.Fatalf("PasswordBreached returned error: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
}
