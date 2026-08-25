// Response compression for the JSON API.
package api

import (
	"net/http"
	"strconv"
	"strings"
)

// minGzipBytes is the payload size below which compressing is a loss: gzip's
// header and trailer alone cost ~23 bytes, and everything under this threshold
// is an ack or a token rather than a screen of mail.
//
// It also keeps the session CSRF token — a ~50-byte JSON response — out of the
// compressor, so no later change can put a secret and attacker-influenced text
// in one compressed body (BREACH).
const minGzipBytes = 1024

// gzipWriter marks a ResponseWriter whose client said it accepts gzip. It
// carries no behaviour of its own: writeJSON type-asserts for it and does the
// compressing, because writeJSON already holds the whole value before a byte
// is written.
//
// Deliberately NOT a compressing ResponseWriter wrapper. That has to sniff
// Content-Type and buffer to decide, and it would sit in front of the static
// asset path too — where http.ServeContent sets Content-Length and answers
// Range requests, both of which transparent re-encoding invalidates.
type gzipWriter struct{ http.ResponseWriter }

func withGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Added even when this response will not be compressed: the decision is
		// per-response size, so one URL legitimately answers both ways and a
		// shared cache must not serve one form for the other.
		w.Header().Add("Vary", "Accept-Encoding")
		if !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(gzipWriter{w}, r)
	})
}

// acceptsGzip reports whether the client will take gzip. "gzip;q=0" is an
// explicit refusal that reads as acceptance to a substring check, and
// "gzip;q=0.9" is an acceptance that reads as refusal to the obvious fix for
// it — which is the whole reason this is a parse and not one strings.Contains.
func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		token, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(token), "gzip") {
			continue
		}
		q, ok := strings.CutPrefix(strings.TrimSpace(params), "q=")
		if !ok {
			return true
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(q), 64)
		return err != nil || v > 0
	}
	return false
}
