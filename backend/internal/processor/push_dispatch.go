package processor

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/health"
	"github.com/Busness-app/kypost-server/backend/internal/retry"
	"github.com/Busness-app/kypost-server/backend/internal/state"

	"github.com/SherClockHolmes/webpush-go"
)

// WebPushOutcome summarizes one SendWebPush call.
type WebPushOutcome struct {
	Subscriptions int
	Sent          int
	Failed        int
	Removed       int
}

// pushFanoutBudget bounds ONE fanout — every destination together, not each.
//
// The per-destination timeouts below bound a single request; they say nothing
// about the total, and both fanouts are serial. state.MaxNotificationSubscriptions
// caps the multiplier, but 20 destinations that each accept the connection and
// then sit there still adds up to minutes — spent on the goroutine poller.tick's
// wg.Wait() is holding the whole instance's polling behind. This is the second
// half of that bound: a fanout gets a fixed slice of wall clock, and whatever
// did not get a turn is counted failed rather than waited for.
//
// A notification is worth a minute of the server's time and no more. The email
// itself has already synced either way.
const pushFanoutBudget = 60 * time.Second

// SendWebPush dispatches payloadBytes to every push subscription in store
// via the standard Web Push protocol, using the VAPID key material at
// privateKeyPath/publicKey and the given ttlSeconds. Subscriptions the push
// service reports as gone (410/404) are removed from store. If store has no
// subscriptions, the VAPID key is never loaded and a zero-value outcome is
// returned. An error is returned only when the VAPID private key could not
// be loaded — per-subscription dispatch failures are reflected in the
// returned outcome, not as an error.
//
// ctx bounds the whole fanout (further capped at pushFanoutBudget) and carries
// cancellation, so a shutdown does not have to wait out a hung push service.
func SendWebPush(ctx context.Context, store *state.Store, publicKey, privateKeyPath string, ttlSeconds int, payloadBytes []byte) (WebPushOutcome, error) {
	subs, err := store.ListNotificationSubscriptionsStrict()
	if err != nil {
		return WebPushOutcome{}, err
	}
	if len(subs) == 0 {
		return WebPushOutcome{}, nil
	}

	privateKey, err := config.LoadVAPIDPrivateKey(privateKeyPath)
	if err != nil {
		return WebPushOutcome{}, err
	}

	options := &webpush.Options{
		Subscriber:      "mailto:noreply@localhost",
		VAPIDPublicKey:  publicKey,
		VAPIDPrivateKey: privateKey,
		TTL:             ttlSeconds,
		// webpush-go otherwise builds a bare &http.Client{} and calls
		// SendNotificationWithContext(context.Background(), ...): no timeout,
		// redirects followed, nothing cancellable. SendWebPush runs inside the
		// goroutine that poller.tick's wg.Wait() awaits, and tick holds a
		// size-1 semaphore across every user — so one endpoint that accepts the
		// connection and never answers stopped mail polling, classification and
		// notification for the whole instance until the container restarted.
		// A hostile endpoint is not required: any push service that hangs
		// rather than refusing produces the same outcome.
		HTTPClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{DialContext: safeDialContext},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	ctx, cancel := context.WithTimeout(ctx, pushFanoutBudget)
	defer cancel()

	sent := 0
	failed := 0
	staleEndpoints := []string{}
	for i, sub := range subs {
		// Budget spent (or shutdown): stop dialling. The rest are counted
		// failed because that is what they are — the notification did not
		// reach them — and reporting them any other way would make an
		// abandoned fanout look like a complete one.
		if ctx.Err() != nil {
			failed += len(subs) - i
			break
		}
		resp, err := webpush.SendNotificationWithContext(ctx, payloadBytes, &webpush.Subscription{
			Endpoint: sub.Endpoint,
			Keys: webpush.Keys{
				Auth:   sub.Auth,
				P256dh: sub.P256DH,
			},
		}, options)
		if err != nil {
			failed++
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusCreated {
			sent++
			continue
		}
		failed++
		if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
			staleEndpoints = append(staleEndpoints, sub.Endpoint)
		}
	}

	removed := 0
	for _, endpoint := range staleEndpoints {
		ok, err := store.RemoveNotificationSubscription(endpoint)
		if err == nil && ok {
			removed++
		}
	}

	return WebPushOutcome{Subscriptions: len(subs), Sent: sent, Failed: failed, Removed: removed}, nil
}

// NativePushOutcome summarizes one SendNativePush call.
type NativePushOutcome struct {
	Devices int
	Sent    int
	Failed  int
	Removed int
	// Queued reports that devices were queued for pull-mode delivery
	// (server-side, fetched by the paired device over plain HTTP) instead of
	// being dispatched through the relay.
	Queued bool
}

// Transient-failure retry for a single device send.
//
// The TODO this replaces read: "a failed send (relay unreachable, upstream 5xx,
// or a 429 when the relay's per-server rate limit is exceeded) currently drops
// the push — the email still syncs in-app, but no notification fires." It sat on
// the delivery path with no backoff, no retry and no circuit breaker, which made
// a one-second relay hiccup indistinguishable from a dead relay: both silently
// lost the notification.
//
// Retried IN-REQUEST, deliberately. A durable queue with its own scheduler is a
// feature — it needs persistence, ordering, a drain worker and a poisoned-message
// story — and it is not what a transient 503 needs. What this covers is the
// common case: the relay was briefly unavailable and is fine a second later.
//
// NOT retried: a stale token (the relay is healthy and pruning), a 4xx that is
// not 429 (the request is wrong; repeating it will not fix it), and anything
// that is not a recognised relay failure. Retrying a permanent error is how a
// dead relay turns into a thread pool full of sleeping goroutines.
//
// A persistent failure still ends at health.RecordNativePushFailure, which is
// what surfaces it — the retry narrows the window, it does not replace the
// signal. What remains unbuilt is re-attempt across requests: a relay down for
// longer than pushRetryAttempts * backoff still drops the notification, and the
// email still syncs in-app. That is the accepted limitation, recorded here
// rather than as a TODO nobody is scheduled to do.
const (
	// nativePushSendTimeout bounds ONE attempt, not the whole retry sequence.
	nativePushSendTimeout = 12 * time.Second

	pushRetryAttempts = 3
	pushRetryBackoff  = 500 * time.Millisecond
	// maxRelayRetryAfter bounds how long a relay-supplied Retry-After may park
	// this send. The value comes from the far end; unbounded, a hostile or broken
	// relay picks how long a goroutine sleeps.
	maxRelayRetryAfter = 5 * time.Second
)

// retryablePushFailure reports whether err is worth another attempt.
func retryablePushFailure(err error) bool {
	if err == nil || errors.Is(err, ErrNativeDeviceStale) {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	// Timeouts and transport failures: the request never produced a response.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	var statusErr *relayStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Code == http.StatusTooManyRequests || statusErr.Code >= 500
	}
	return false
}

// pushRetryDelay is the wait before the next attempt: the relay's own
// Retry-After when it supplied one, otherwise exponential backoff.
func pushRetryDelay(err error, attempt int) time.Duration {
	var statusErr *relayStatusError
	if errors.As(err, &statusErr) && statusErr.RetryAfter > 0 {
		return statusErr.RetryAfter
	}
	return pushRetryBackoff << attempt
}

// sendWithRetry dispatches one device's notification, retrying transient
// failures. Each attempt gets its own timeout derived from ctx.
func sendWithRetry(ctx context.Context, dispatcher *NativePushDispatcher, device state.NativeDevice, message NativePushMessage) error {
	var lastErr error
	_, err := retry.Loop(ctx, pushRetryAttempts,
		// The loop's own attempt counter, not a hardcoded 0. Pinning it to 0
		// made pushRetryDelay's shift a no-op, so every "exponential" backoff
		// was the same flat 500ms — the retries an outage produces arrived at a
		// constant rate against a relay that was already failing.
		func(attempt int) time.Duration { return pushRetryDelay(lastErr, attempt) },
		func(attempt int) (struct{}, error, bool) {
			sendCtx, cancel := context.WithTimeout(ctx, nativePushSendTimeout)
			defer cancel()
			err := dispatcher.Send(sendCtx, device, message)
			lastErr = err
			return struct{}{}, err, retryablePushFailure(err)
		})
	if err != nil {
		return err
	}
	return nil
}

// SendNativePush dispatches message to every native device registered in
// store. See SendNativePushToDevices for the delivery semantics; this is a
// thin wrapper that targets every device in store.
func SendNativePush(ctx context.Context, dispatcher *NativePushDispatcher, healthSvc *health.Service, store *state.Store, message NativePushMessage, onDeviceError func(device state.NativeDevice, platform string, err error)) (NativePushOutcome, error) {
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		return NativePushOutcome{}, err
	}
	return SendNativePushToDevices(ctx, dispatcher, healthSvc, store, devices, message, onDeviceError)
}

// SendNativePushToDevices dispatches message to exactly the devices given (a
// caller-filtered subset, e.g. push-2FA's approver-eligible devices — or, via
// SendNativePush, every device in store). If the store's delivery mode is
// pull, devices are enqueued server-side instead of being sent through the
// relay/Firebase (Sent is set to 1 to indicate the queue write succeeded).
// Otherwise every device is dispatched through dispatcher, each with its own
// timeout derived from ctx, stale devices (ErrNativeDeviceStale) are removed
// from store, and relay health is recorded on healthSvc per platform.
// onDeviceError, if non-nil, is called for every non-stale dispatch failure so
// callers can log with their own context.
func SendNativePushToDevices(ctx context.Context, dispatcher *NativePushDispatcher, healthSvc *health.Service, store *state.Store, devices []state.NativeDevice, message NativePushMessage, onDeviceError func(device state.NativeDevice, platform string, err error)) (NativePushOutcome, error) {
	if len(devices) == 0 {
		return NativePushOutcome{}, nil
	}

	if store.NativeDeliveryMode() == state.DeliveryModePull {
		if err := store.EnqueuePullNotification(state.PullNotification{Title: message.Title, Body: message.Body, Data: message.Data}); err != nil {
			return NativePushOutcome{Devices: len(devices), Queued: true}, err
		}
		return NativePushOutcome{Devices: len(devices), Sent: 1, Queued: true}, nil
	}

	// The whole fanout, not each device: three attempts at nativePushSendTimeout
	// apiece, times every paired device, is otherwise the bound. See
	// pushFanoutBudget.
	ctx, cancel := context.WithTimeout(ctx, pushFanoutBudget)
	defer cancel()

	sent := 0
	failed := 0
	removed := 0
	// Track relay health per platform. A response from the relay (success or
	// stale token) means the relay answered; only non-stale errors mean the
	// relay is failing.
	relayResponded := make(map[string]bool) // platform -> responded
	relayFailure := make(map[string]string) // platform -> failure reason
	for i, device := range devices {
		if ctx.Err() != nil {
			failed += len(devices) - i
			break
		}
		platform := strings.ToLower(strings.TrimSpace(device.Platform))
		if platform == "" {
			platform = "android" // default for unknown/empty
		}

		err := sendWithRetry(ctx, dispatcher, device, message)
		if err != nil {
			failed++
			if errors.Is(err, ErrNativeDeviceStale) {
				// The relay responded (410 stale) — that is a healthy relay
				// pruning a dead token, not a relay failure.
				relayResponded[platform] = true
				if strings.TrimSpace(device.DeviceID) != "" {
					if ok, rmErr := store.RemoveNativeDevice(device.DeviceID); rmErr == nil && ok {
						removed++
					}
				}
			} else {
				// A coarse classification, never err.Error(). This value is
				// recorded on health.Status.NativePushLastError, which the
				// UNAUTHENTICATED /api/health publishes — and the error text
				// carries both the endpoint URL (which for UnifiedPush *is*
				// the device's push credential) and up to 8 KiB of the remote
				// server's response body, which a user pointing a device at
				// their own host controls outright. See
				// classifyNativePushFailure.
				relayFailure[platform] = classifyNativePushFailure(platform, err)
			}
			if onDeviceError != nil {
				onDeviceError(device, platform, err)
			}
			continue
		}

		relayResponded[platform] = true
		sent++
	}

	// Update health per platform: record failures once per platform that
	// failed, and successes for platforms that responded without failure.
	for _, failure := range relayFailure {
		healthSvc.RecordNativePushFailure(failure)
	}
	for platform := range relayResponded {
		if _, hasFailed := relayFailure[platform]; !hasFailed {
			healthSvc.RecordNativePushSuccess()
		}
	}

	return NativePushOutcome{Devices: len(devices), Sent: sent, Failed: failed, Removed: removed}, nil
}
