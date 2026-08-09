# Findings Detail — run-12

## HIGH — Pre-revocation native pairing token can recreate a device during credential purge

The attacker submits `POST /api/notifications/native/register` with a still-valid old `subscriberId` and `pairingToken`, plus a new valid `deviceId` and attacker-controlled push token. `server_notifications.go:431-450` validates the signed token and `:460-465` resolves the owner. Concurrently, the administrator calls password reset, MFA clear, or deactivation. `server_userscope.go:761-775` revokes sessions, deletes native devices, and removes CardDAV credentials; `:776-800` rotates the subscriber only afterward. The registration continues using the already-resolved owner; `server_notifications.go:513-556` consumes the nonce, reserves the new ID, and persists a new native device. It never rechecks the current subscriber generation or account state.

```http
POST /api/notifications/native/register
Content-Type: application/json

{"subscriberId":"<old-subscriber-id>","pairingToken":"<old-valid-token>","deviceToken":"<attacker-token>","deviceId":"attacker-device","platform":"android","transport":"fcm"}
```

The attacker must already possess the valid pairing token. MFA clear is the direct impact case: the account stays active and the newly persisted device can authenticate to mail routes. Deactivation leaves the device for reactivation.

The release workflow’s mutable third-party action tags were reviewed as a hardening item. The workflow has powerful package/attestation permissions, but the attack requires an external action-tag compromise or equivalent upstream control; source review alone cannot confirm that deployment condition. It is therefore not represented as a confirmed finding.
