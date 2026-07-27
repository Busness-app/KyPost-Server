package processor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/health"
	"kypost-server/backend/internal/state"

	"github.com/SherClockHolmes/webpush-go"
)

// WebPushOutcome summarizes one SendWebPush call.
type WebPushOutcome struct {
	Subscriptions int
	Sent          int
	Failed        int
	Removed       int
}

// SendWebPush dispatches payloadBytes to every push subscription in store
// via the standard Web Push protocol, using the VAPID key material at
// privateKeyPath/publicKey and the given ttlSeconds. Subscriptions the push
// service reports as gone (410/404) are removed from store. If store has no
// subscriptions, the VAPID key is never loaded and a zero-value outcome is
// returned. An error is returned only when the VAPID private key could not
// be loaded — per-subscription dispatch failures are reflected in the
// returned outcome, not as an error.
func SendWebPush(store *state.Store, publicKey, privateKeyPath string, ttlSeconds int, payloadBytes []byte) (WebPushOutcome, error) {
	subs := store.ListNotificationSubscriptions()
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

	sent := 0
	failed := 0
	staleEndpoints := []string{}
	for _, sub := range subs {
		resp, err := webpush.SendNotification(payloadBytes, &webpush.Subscription{
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

// SendNativePush dispatches message to every native device registered in
// store. See SendNativePushToDevices for the delivery semantics; this is a
// thin wrapper that targets every device in store.
func SendNativePush(ctx context.Context, dispatcher *NativePushDispatcher, healthSvc *health.Service, store *state.Store, message NativePushMessage, onDeviceError func(device state.NativeDevice, platform string, err error)) (NativePushOutcome, error) {
	return SendNativePushToDevices(ctx, dispatcher, healthSvc, store, store.ListNativeDevices(), message, onDeviceError)
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

	sent := 0
	failed := 0
	removed := 0
	// Track relay health per platform. A response from the relay (success or
	// stale token) means the relay answered; only non-stale errors mean the
	// relay is failing.
	relayResponded := make(map[string]bool) // platform -> responded
	relayFailure := make(map[string]string) // platform -> failure reason
	for _, device := range devices {
		platform := strings.ToLower(strings.TrimSpace(device.Platform))
		if platform == "" {
			platform = "android" // default for unknown/empty
		}

		sendCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		err := dispatcher.Send(sendCtx, device, message)
		cancel()
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
				// Prefix the failure reason with the platform for diagnostics.
				relayFailure[platform] = fmt.Sprintf("[%s] %s", platform, err.Error())
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
