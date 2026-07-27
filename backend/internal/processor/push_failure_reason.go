package processor

import (
	"context"
	"errors"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// nativePushFailureReasons is the closed vocabulary of values that may reach
// health.Status.NativePushLastError, which the UNAUTHENTICATED /api/health
// serializes to anyone who asks.
//
// A closed set rather than a formatted message is the whole point. This field
// used to carry err.Error() verbatim, and two things ride along in those
// strings:
//
//   - http.Client wraps transport failures in *url.Error, whose Error() prints
//     the full request URL. For a UnifiedPush device the endpoint URL *is* the
//     credential — anyone holding https://ntfy.sh/<private-topic> can push to
//     that device — so every connection refusal published one user's push
//     credential on a public endpoint.
//   - the UnifiedPush sender embeds up to 8 KiB of the remote server's raw
//     response body. A user may point a device at any host they control, so
//     that is an arbitrary-text write onto the instance's anonymous health
//     JSON, by an authenticated user, against every reader of it.
//
// Operators lose nothing that matters: which platform is failing and roughly
// why is what drives the next action, and the full error is still logged.
var nativePushFailureReasons = map[string]bool{
	"unreachable":  true, // DNS, TCP, TLS — the relay or endpoint could not be contacted
	"timeout":      true, // contacted, did not answer in time
	"unauthorized": true, // 401/403 — usually an orphaned or rotated relay key
	"rate_limited": true, // 429
	"server_error": true, // 5xx at the far end
	"rejected":     true, // any other non-2xx
	"failed":       true, // recognised as a failure, but not as any of the above
}

// statusCodePattern pulls the "status=NNN" this package's senders format into
// their errors. Matching our own format is deliberate: the alternative is
// scanning the whole error string for three digits, which would happily find
// them inside an attacker-supplied response body.
var statusCodePattern = regexp.MustCompile(`\bstatus=(\d{3})\b`)

// classifyNativePushFailure reduces a send error to "[platform] reason", where
// reason is drawn from nativePushFailureReasons and nothing else.
//
// Every branch returns a constant. No branch interpolates any part of err, so
// there is no path — including one added later for an error shape nobody has
// seen yet — by which a URL or a remote response body reaches the caller. The
// caller records this on the public health status; the full error belongs in
// the log.
func classifyNativePushFailure(platform string, err error) string {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" {
		platform = "unknown"
	}
	return "[" + platform + "] " + nativePushFailureReason(err)
}

func nativePushFailureReason(err error) string {
	if err == nil {
		return "failed"
	}

	// Timeouts first: a deadline exceeded on the way to connecting is still
	// better described as a timeout than as unreachable.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return "timeout"
		}
		// A *url.Error means the request never produced an HTTP response —
		// DNS, TCP, TLS, or a refused redirect.
		return "unreachable"
	}

	if m := statusCodePattern.FindStringSubmatch(err.Error()); m != nil {
		code, convErr := strconv.Atoi(m[1])
		if convErr == nil {
			switch {
			case code == 401 || code == 403:
				return "unauthorized"
			case code == 429:
				return "rate_limited"
			case code >= 500:
				return "server_error"
			case code >= 400:
				return "rejected"
			}
		}
	}

	return "failed"
}
