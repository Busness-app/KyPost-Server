package api

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAcceptsGzip(t *testing.T) {
	cases := []struct {
		header string
		want   bool
	}{
		{"", false},
		{"gzip", true},
		{"gzip, deflate, br", true},
		{"deflate, gzip;q=1.0, *;q=0.5", true},
		{"gzip;q=0.9", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"deflate, gzip;q=0", false},
		{"GZIP", true},
		{" gzip ", true},
		{"identity", false},
		{"x-gzip", false},
	}
	for _, tc := range cases {
		if got := acceptsGzip(tc.header); got != tc.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

// bigPayload is comfortably over minGzipBytes and compresses well, like the
// inbox list this exists for.
func bigPayload() map[string]any {
	items := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		items = append(items, "notifications@marketing.example.com")
	}
	return map[string]any{"items": items}
}

func TestWriteJSONCompressesLargeResponses(t *testing.T) {
	handler := withGzip(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, bigPayload())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/inbox", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("Vary = %q, want it to include Accept-Encoding", got)
	}

	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip body: %v", err)
	}
	if !strings.HasPrefix(string(plain), `{"items":[`) {
		t.Fatalf("decompressed body is not the JSON written: %.60s", plain)
	}
	if rec.Body.Len() >= len(plain) {
		t.Errorf("compressed %d bytes is not smaller than plain %d", rec.Body.Len(), len(plain))
	}
}

func TestWriteJSONLeavesSmallAndUnwillingResponsesAlone(t *testing.T) {
	cases := []struct {
		name           string
		acceptEncoding string
		payload        any
	}{
		// A CSRF token response: a secret, and far under the threshold.
		{"below the size threshold", "gzip", map[string]any{"csrfToken": "deadbeef"}},
		{"client did not offer gzip", "", bigPayload()},
		{"client refused gzip", "gzip;q=0", bigPayload()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := withGzip(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, tc.payload)
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
			if tc.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tc.acceptEncoding)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Fatalf("Content-Encoding = %q, want none", got)
			}
			if !strings.HasPrefix(rec.Body.String(), "{") {
				t.Fatalf("body is not plain JSON: %.60s", rec.Body.String())
			}
		})
	}
}

// The static asset path writes through http.ServeContent, which sets
// Content-Length and honours Range. withGzip must not touch it.
func TestWithGzipLeavesNonJSONWritersUntouched(t *testing.T) {
	handler := withGzip(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.Repeat("<p>hello</p>", 500)))
	}))
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if rec.Body.Len() != 500*len("<p>hello</p>") {
		t.Fatalf("body length = %d, want it passed through unchanged", rec.Body.Len())
	}
}
