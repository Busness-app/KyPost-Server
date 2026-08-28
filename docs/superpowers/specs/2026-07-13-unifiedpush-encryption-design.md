# UnifiedPush server-side encryption (RFC 8291)

> **Status: IMPLEMENTED 2026-08-26**, on branch `feat/unifiedpush-rfc8291`.
> Two deviations from the plan below, both forced by drift since it was written:
> the state store moved to SQLite, so `P256DH`/`Auth` needed two columns via
> `additiveColumns` rather than two struct fields; and `Redacted()` now clears
> `Auth`, which this design did not consider — with the endpoint URL it is a
> notification-forgery capability. Decision 3 ("MFA exclusion out of scope") was
> subsequently reversed by the user: `MFATransportEligible` now allows a
> UnifiedPush device that supplied keys, since the reason for the blanket
> exclusion was the plaintext payload this change removes.

## Problem

UnifiedPush does not provide transport encryption itself — the app server must
encrypt every payload with the Web Push Encryption standard (RFC 8291) before
POSTing it to the subscriber's endpoint URL. The backend currently POSTs
UnifiedPush payloads as plaintext JSON. The Android client's UnifiedPush
receiver has already been fixed to drop any message it cannot decrypt
(`message.decrypted == false`), so every UnifiedPush notification is now
silently lost. This is the matching server-side half of that client fix.

The client fix (already merged in `llama-mobile`) has the UnifiedPush
connector generate a WebPush keypair per endpoint and send the public parts
— `p256dh` and `auth` — to the registration endpoint as two new optional
fields on `NativeRegistrationRequest`, present only when
`transport == "unifiedpush"`. The server needs to store these and use them to
encrypt outgoing payloads.

## Existing building blocks

- `github.com/SherClockHolmes/webpush-go` is already a dependency, already
  used for browser Web Push in `processor.SendWebPush`
  (`backend/internal/processor/push_dispatch.go`), including VAPID signing.
- A VAPID keypair is already generated and persisted at
  `cfg.Notifications.PrivateKeyPath` / `cfg.Notifications.PublicKey`
  (`config.ensureNotificationKeyMaterial`, run during config load, so it
  exists before `NewServer`/`poller.New` construct anything).
- `state.NotificationSubscription` already has `P256DH`/`Auth` fields for
  browser push subscriptions — this change mirrors that naming on
  `NativeDevice`.
- `processor.UnifiedPushSender` already POSTs directly to the UnifiedPush
  endpoint through an SSRF-hardened `*http.Client`
  (`safeDialContext` + redirects disabled) — the encrypted path must reuse
  this same client so SSRF protection isn't lost.

## Decisions

1. **VAPID keys**: reuse the existing browser-push VAPID keypair. No new key
   file, no new config. VAPID here is just an auth JWT header; most
   UnifiedPush distributors don't validate it, so sharing identity across
   transports is low-risk and avoids new key-management surface.
2. **Missing key material** (old client build, or a distributor whose
   connector didn't supply `pubKeySet`): fall back to today's unencrypted
   POST. No regression for anyone until they're on a client that sends keys.
3. **MFA push-2FA exclusion**: out of scope. UnifiedPush devices stay
   excluded from MFA challenges regardless of whether they have key
   material. Lifting that restriction is a separate follow-up.

## Changes

### `backend/internal/state/store.go`

Add to `NativeDevice`:

```go
// P256DH and Auth are the WebPush (RFC 8291) subscription keys the
// UnifiedPush connector generated for this endpoint. Present only for
// transport == "unifiedpush"; used to encrypt payloads so the connector can
// decrypt them on receipt. Mirrors NotificationSubscription's fields.
P256DH string `json:"p256dh,omitempty"`
Auth   string `json:"auth,omitempty"`
```

### `backend/internal/api/server.go`

- `nativeRegisterRequest` gets `P256DH string json:"p256dh,omitempty"` and
  `Auth string json:"auth,omitempty"`.
- In `handleNotificationNativeRegister`, when `transport == "unifiedpush"`
  and either key is non-empty, validate with
  `processor.ValidateWebPushKeys(p256dh, auth)` (new function, see below).
  Reject with `400` on validation failure, same pattern as the existing
  `ValidateUnifiedPushEndpointURL` check just above it. Missing keys (both
  empty) are allowed.
- Store validated `P256DH`/`Auth` (trimmed) on the `state.NativeDevice`
  only when `transport == "unifiedpush"`, so other transports' records never
  carry stray key material.

### `backend/internal/processor/native_sender.go`

New function:

```go
// ValidateWebPushKeys checks that p256dh and auth are well-formed WebPush
// (RFC 8291) subscription keys: p256dh must decode to a 65-byte uncompressed
// P-256 point (0x04 prefix), auth to a 16-byte secret. Both must be present
// together, or both absent — partial key material can't encrypt anything.
func ValidateWebPushKeys(p256dh, auth string) error
```

Uses a small `decodeWebPushKey` helper that tries
`RawURLEncoding`/`URLEncoding`/`RawStdEncoding`/`StdEncoding` in turn (same
leniency `webpush-go`'s own `decodeSubscriptionKey` has), so validation never
rejects something the sender would later accept.

`UnifiedPushSender`:

- New fields `vapidPublicKey`, `vapidPrivateKey string`.
- `NewUnifiedPushSender(log *logging.Logger, vapidPublicKey, vapidPrivateKeyPath string) *UnifiedPushSender`
  replaces the current no-arg constructor. Loads the private key once via
  `config.LoadVAPIDPrivateKey` at construction time. If loading fails, logs
  and leaves `vapidPrivateKey` empty rather than failing construction —
  construction must never fail here, since the sender still works
  unencrypted.
- `Send()`: builds the same JSON payload as today. If the device has both
  `P256DH` and `Auth` set *and* the sender has a loaded VAPID private key,
  encrypts via `webpush.SendNotificationWithContext`, passing `s.client`
  (the existing SSRF-hardened client) as `Options.HTTPClient` and the
  server's VAPID keys/`"mailto:noreply@localhost"` subscriber (matching
  `SendWebPush`'s existing convention) with `TTL: 300`. Otherwise, sends
  today's exact plaintext POST.
- Status-code interpretation (2xx → success, 404/410 → stale, else → error)
  is extracted into a shared helper used by both the encrypted and
  plaintext paths, since both need identical stale-detection semantics.

`NewNativePushDispatcher(log *logging.Logger, vapidPublicKey, vapidPrivateKeyPath string) *NativePushDispatcher`
gains the two new params and threads them to `NewUnifiedPushSender`.

### Call sites

Both already have `cfg` in scope:

- `backend/internal/api/server.go:121` →
  `processor.NewNativePushDispatcher(logger, cfg.Notifications.PublicKey, cfg.Notifications.PrivateKeyPath)`
- `backend/internal/processor/poller.go:93` →
  `NewNativePushDispatcher(log, cfg.Notifications.PublicKey, cfg.Notifications.PrivateKeyPath)`

## Error handling

- Malformed keys at registration → `400`, same shape as the existing
  endpoint-URL validation error.
- Missing VAPID private key at dispatcher construction → logged, sender
  falls back to unencrypted sends (never a hard failure).
- Per-device send failures (encrypted or not) are handled exactly as today:
  `ErrNativeDeviceStale` on 404/410 triggers device cleanup; other errors are
  surfaced to `onDeviceError` and recorded as relay-health failures.

## Testing

- `ValidateWebPushKeys`: valid pair, bad length (p256dh, auth), invalid
  base64, one-sided (p256dh only / auth only) — each should error except the
  fully-valid and fully-absent cases.
- `UnifiedPushSender.Send`:
  - Encrypted path, using a real generated P-256 test keypair: asserts
    `Content-Encoding: aes128gcm` request header and a non-JSON ciphertext
    body.
  - Plaintext fallback when device keys are absent (existing test, comment
    updated to state it's the fallback case).
  - Plaintext fallback when device keys are present but the sender has no
    loaded VAPID key (construction-failure fallback case).
- Registration handler: `400` on malformed `p256dh`/`auth`; device persisted
  with keys on a valid pair; device persisted without keys when both are
  absent.
- Update the ~6 existing `NewUnifiedPushSender()` / `NewNativePushDispatcher()`
  call sites in `native_sender_test.go` and `push_dispatch_test.go` for the
  new constructor signatures (empty-string VAPID args where a test doesn't
  care about encryption).

## Out of scope

- Lifting the MFA push-2FA UnifiedPush exclusion.
- Any change to `UNIFIEDPUSH_IMPLEMENTATION.md`'s "Future Work" item 2–4.
- Android client changes (already merged).
