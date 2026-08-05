# Device Enrollment 2b (Browser) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the browser the ability to verify a paired device's published public key against a code the user types from that device's screen, and — only on a match — seal the account's PGP private key to it.

**Architecture:** A new self-contained `DeviceEnrollmentCard` on the Security page reads the paired-device list through a new shared API module, renders each device's enrollment state, and runs the ceremony in a dialog. The ceremony captures the device's public key once, refuses on a locked vault, refuses on a code mismatch **before issuing any request**, and only then seals and `PUT`s. A separate diagnostic function, downstream of the refusal, decides whether the copy says "expired" or "substituted".

**Tech Stack:** React 19, TypeScript 7, Vitest 4 + @testing-library/react under jsdom, WebCrypto (real, not mocked, in tests).

## Global Constraints

- **The security of this feature is one comparison.** On mismatch the browser refuses to seal. Never seal-then-verify, never offer a way to proceed past a mismatch.
- **Never modify `verifyEnrollmentCode`, `deriveEnrollmentCode`, `sealEnvelopeForDevice`, or any constant in `frontend/src/lib/deviceEnrollment.ts`.** They are shipped, tested, and normative across three client implementations. This plan only *adds* to that file, in Task 3.
- **The test vector `5R9K6FWA18`** in `frontend/src/lib/deviceEnrollment.test.ts` is authoritative over every document. A change to it is a wire-format break, not a test update.
- **Two credentials, never one.** The vault passphrase (`requireUnlockedKey`) and the account password (step-up for the `PUT`) are separate strings and separate inputs. They differ in the stale-envelope recovery path already on `SecurityPage`.
- Slot name is `` `device:${encodeURIComponent(deviceId)}` `` — prefix literal, id escaped.
- Envelope alg string is exactly `ECDH-P256+HKDF-SHA256+A256GCM`.
- All work is in `frontend/`. Run tests with `npx vitest run <path>` from `frontend/`.
- House test style: `vi.mock` the API modules, `@testing-library/react` with `userEvent`, assert on elements with `toBeTruthy()` / `toBeNull()` — **jest-dom is not installed**, so `toBeInTheDocument` does not exist.
- Commit after every task. Branch is `perf/bound-lockout-tests` (the enrollment work already lives there).

---

### Task 1: Shared paired-device API module

Today `NotificationsPage.tsx:46` declares a private `NativeDevice` type that is stale by the three enrollment fields the server already serves. Both pages need the same shape, so it moves to one module. A shared *fetch helper* only — not a shared render component, because the two lists answer different questions about the same phone.

**Files:**
- Create: `frontend/src/api/devices.ts`
- Create: `frontend/src/api/devices.test.ts`
- Modify: `frontend/src/pages/NotificationsPage.tsx` (delete the local type at lines 46-60; use the new module at line 433)

**Interfaces:**
- Consumes: `getJSON` from `frontend/src/api/client.ts`.
- Produces: `type NativeDevice` and `listNativeDevices(): Promise<{ devices: NativeDevice[] }>`, used by Tasks 4-7.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/api/devices.test.ts`:

```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { listNativeDevices } from "./devices";

const getJSON = vi.fn();
vi.mock("./client", () => ({ getJSON: (path: string) => getJSON(path) }));

beforeEach(() => {
  getJSON.mockReset();
});

describe("listNativeDevices", () => {
  // The three enrollment fields are the whole reason this module exists:
  // NotificationsPage's private copy of the type predates them, so a device
  // that HAS published a key read as one that had not.
  it("passes the enrollment fields through", async () => {
    getJSON.mockResolvedValue({
      devices: [
        {
          deviceId: "d1",
          platform: "android",
          pushToken: "tok",
          enrollmentPublicKey: "BASE64KEY",
          enrollmentKeyAt: "2026-08-05T10:00:00Z",
          encryptionEnrolled: true
        }
      ]
    });

    const { devices } = await listNativeDevices();

    expect(getJSON).toHaveBeenCalledWith("/api/notifications/native/devices");
    expect(devices[0].enrollmentPublicKey).toBe("BASE64KEY");
    expect(devices[0].encryptionEnrolled).toBe(true);
  });

  it("reads a device that has published nothing as unenrolled", async () => {
    getJSON.mockResolvedValue({
      devices: [{ deviceId: "d2", platform: "ios", pushToken: "tok", encryptionEnrolled: false }]
    });

    const { devices } = await listNativeDevices();

    expect(devices[0].enrollmentPublicKey).toBeUndefined();
    expect(devices[0].encryptionEnrolled).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npx vitest run src/api/devices.test.ts`
Expected: FAIL — `Failed to resolve import "./devices"`.

- [ ] **Step 3: Write the module**

Create `frontend/src/api/devices.ts`:

```ts
import { getJSON } from "./client";

/**
 * A paired native device, as GET /api/notifications/native/devices serves it.
 *
 * Mirrors state.NativeDevice's JSON tags (backend/internal/state/store.go:67)
 * after Redacted() strips the secret hash.
 *
 * This type lives here rather than on a page because two pages now need it and
 * they drifted: NotificationsPage's private copy predates the enrollment
 * fields, so every device read as never having published a key. The fetch is
 * shared; the RENDERING deliberately is not, because "which device can approve
 * a sign-in" and "which device can read my mail" are different questions that
 * have no reason to change together.
 */
export type NativeDevice = {
  deviceId: string;
  platform: string;
  pushToken: string;
  deviceName?: string;
  appVersion?: string;
  userAgent?: string;
  registeredAt?: string;
  updatedAt?: string;
  transport?: string;
  /**
   * The device's EC P-256 public key for encrypted mail: base64 of the
   * uncompressed SEC1 point. Absent until the device publishes one, which is
   * what makes the enrollment UI self-gating before the mobile half ships.
   */
  enrollmentPublicKey?: string;
  enrollmentKeyAt?: string;
  /**
   * DEVICE-REPORTED: whether it can still open its local envelope. Not the
   * server's opinion — reinstalling the app destroys the key that answers this,
   * so the device re-reports it on every registration.
   */
  encryptionEnrolled: boolean;
};

export function listNativeDevices(): Promise<{ devices: NativeDevice[] }> {
  return getJSON<{ devices: NativeDevice[] }>("/api/notifications/native/devices");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npx vitest run src/api/devices.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Point NotificationsPage at the shared module**

In `frontend/src/pages/NotificationsPage.tsx`, delete the local `NativeDevice` type (lines 46-56) and `NativeDevicesResponse` (lines 58-60). Add to the imports:

```ts
import { listNativeDevices, type NativeDevice } from "../api/devices";
```

Replace the fetch inside `refreshNativeDevices` (line 433):

```ts
      const next = await listNativeDevices();
```

Leave everything else on that page alone — `summarizeDevice`, `deviceTransport`, and the render all keep working against the identical shape.

- [ ] **Step 6: Verify nothing regressed**

Run: `cd frontend && npx tsc --noEmit && npx vitest run`
Expected: tsc clean; the whole suite passes.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api/devices.ts frontend/src/api/devices.test.ts frontend/src/pages/NotificationsPage.tsx
git commit -m "refactor(devices): share the paired-device type, stale by enrollment"
```

---

### Task 2: Envelope slot API client

Change 1 shipped `PUT`/`DELETE /api/pgp/identity/envelope/{slot}` with no browser consumer at all. No `GET` client is written: the browser never reads a slot back — the device reads its own over the narrow `withMailAuth` route — and adding the one call with no caller is how dead code arrives.

**Files:**
- Modify: `frontend/src/api/pgp.ts` (append after `createSealedPickup`, line 333)
- Create: `frontend/src/api/pgp.test.ts`

**Interfaces:**
- Consumes: `putJSON`, `deleteJSON` from `./client`; the private `stepUp(password)` helper already in `pgp.ts:55`; `type DeviceEnvelope` from `../lib/deviceEnrollment`.
- Produces: `putDeviceEnvelope(deviceId: string, envelope: DeviceEnvelope, password: string): Promise<{ ok: boolean }>` and `deleteDeviceEnvelope(deviceId: string, password: string): Promise<{ ok: boolean }>`, used by Tasks 5 and 7.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/api/pgp.test.ts`:

```tsx
import { beforeEach, describe, expect, it, vi } from "vitest";
import { deleteDeviceEnvelope, putDeviceEnvelope } from "./pgp";
import type { DeviceEnvelope } from "../lib/deviceEnrollment";

const putJSON = vi.fn();
const deleteJSON = vi.fn();

vi.mock("./client", () => ({
  getJSON: vi.fn(),
  postJSON: vi.fn(),
  putJSON: (path: string, body: unknown) => putJSON(path, body),
  deleteJSON: (path: string, body: unknown) => deleteJSON(path, body)
}));

// stepUp derives a credential the server can verify; the shape is auth.ts's
// business, so this pins only that the step-up IS attached.
vi.mock("./auth", () => ({
  deriveCredential: async () => ({ kind: "test" }),
  credentialFields: () => ({ password: "hunter2" })
}));

const ENVELOPE: DeviceEnvelope = {
  v: 1,
  alg: "ECDH-P256+HKDF-SHA256+A256GCM",
  epk: "EPK",
  iv: "IV",
  ct: "CT"
};

beforeEach(() => {
  putJSON.mockReset();
  deleteJSON.mockReset();
  putJSON.mockResolvedValue({ ok: true });
  deleteJSON.mockResolvedValue({ ok: true });
});

describe("putDeviceEnvelope", () => {
  it("writes the device slot with the id escaped and the prefix literal", async () => {
    await putDeviceEnvelope("dev:1", ENVELOPE, "hunter2");

    expect(putJSON).toHaveBeenCalledWith("/api/pgp/identity/envelope/device:dev%3A1", {
      envelope: JSON.stringify(ENVELOPE),
      password: "hunter2"
    });
  });
});

describe("deleteDeviceEnvelope", () => {
  // The route decodes the body unconditionally and 400s a bodyless request
  // rather than treating it as "no credential needed" — so the credential must
  // travel in the body, not as a query parameter.
  it("sends the step-up in the body", async () => {
    await deleteDeviceEnvelope("dev:1", "hunter2");

    expect(deleteJSON).toHaveBeenCalledWith("/api/pgp/identity/envelope/device:dev%3A1", {
      password: "hunter2"
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npx vitest run src/api/pgp.test.ts`
Expected: FAIL — `putDeviceEnvelope is not a function` (or an import error naming it).

- [ ] **Step 3: Write the implementation**

At the top of `frontend/src/api/pgp.ts`, add the type-only import:

```ts
import type { DeviceEnvelope } from "../lib/deviceEnrollment";
```

Append to the end of `frontend/src/api/pgp.ts`:

```ts
// ---- device enrollment slots -----------------------------------------------

/**
 * Installs a device's ECDH-sealed envelope in its `device:<id>` slot.
 *
 * CALLERS MUST HAVE VERIFIED THE ENROLLMENT CODE FIRST. This request is what
 * the comparison in DeviceEnrollmentCard gates: by the time it is issued the
 * private key is ALREADY sealed to whatever public key the server served, so
 * nothing here or downstream can undo a decision made upstream of it. The
 * function cannot check that for itself, which is exactly why the gate belongs
 * at the call site.
 *
 * `password` is the ACCOUNT credential the route's step-up requires — not the
 * vault passphrase, which the stale-envelope recovery path proves may differ.
 */
export async function putDeviceEnvelope(
  deviceId: string,
  envelope: DeviceEnvelope,
  password: string
): Promise<{ ok: boolean }> {
  return putJSON<{ ok: boolean }>(`/api/pgp/identity/envelope/device:${encodeURIComponent(deviceId)}`, {
    envelope: JSON.stringify(envelope),
    ...(await stepUp(password))
  });
}

/**
 * Removes the server's transport copy of a device's sealing.
 *
 * This is weaker than it sounds and the UI must not imply otherwise: it removes
 * the server's copy only. Once the device has fetched that envelope and
 * re-sealed it under its own keystore key, the server has no reach into it at
 * all, and revoking that device means rotating the identity.
 */
export async function deleteDeviceEnvelope(deviceId: string, password: string): Promise<{ ok: boolean }> {
  return deleteJSON<{ ok: boolean }>(
    `/api/pgp/identity/envelope/device:${encodeURIComponent(deviceId)}`,
    await stepUp(password)
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npx vitest run src/api/pgp.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/api/pgp.ts frontend/src/api/pgp.test.ts
git commit -m "feat(pgp): give the envelope slot routes a browser client"
```

---

### Task 3: Tell expiry apart from substitution

The parent spec requires the browser report expiry distinctly from mismatch — "they mean different things and only one of them is alarming" — without saying how. It cannot be done with the gate alone: `verifyEnrollmentCode` returns `false` for a stale code and a substituted key alike, by construction.

This adds a **diagnostic**, not a second gate. It runs only after the gate has already refused, and its answer selects copy. The separation is the point: `verifyEnrollmentCode` stays exactly as shipped, so no conclusion reached here can widen what gets sealed.

**Files:**
- Modify: `frontend/src/lib/deviceEnrollment.ts` (append only — change nothing above)
- Modify: `frontend/src/lib/deviceEnrollment.test.ts` (append a new `describe`)

**Interfaces:**
- Consumes: `normalizeEnrollmentCode`, `deriveEnrollmentCode`, `bucketFor`, and the module-private `CROCKFORD`, `CODE_LENGTH`, `codesEqual`.
- Produces: `type EnrollmentFailure = "malformed" | "expired" | "mismatch"` and `explainEnrollmentFailure(publicKeyB64, deviceId, typed, nowUnixSeconds?): Promise<EnrollmentFailure>`, used by Task 6.

- [ ] **Step 1: Write the failing test**

Append to `frontend/src/lib/deviceEnrollment.test.ts`. Add `explainEnrollmentFailure` to the existing import list at the top of the file, then:

```ts
describe("explainEnrollmentFailure", () => {
  it("reads a code from an older bucket as expired", async () => {
    const stale = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET - 6);
    const why = await explainEnrollmentFailure(
      VECTOR_KEY_B64,
      VECTOR_DEVICE_ID,
      stale,
      VECTOR_UNIX_SECONDS
    );
    expect(why).toBe("expired");
  });

  it("reads a code derived from a different key as a mismatch", async () => {
    const other = new Uint8Array(RAW_KEY);
    other[1] = 0x09;
    const otherB64 = btoa(String.fromCharCode(...other));
    const substituted = await deriveEnrollmentCode(otherB64, VECTOR_DEVICE_ID, VECTOR_BUCKET);

    const why = await explainEnrollmentFailure(
      VECTOR_KEY_B64,
      VECTOR_DEVICE_ID,
      substituted,
      VECTOR_UNIX_SECONDS
    );
    expect(why).toBe("mismatch");
  });

  it("reads a short entry as malformed rather than alarming", async () => {
    const why = await explainEnrollmentFailure(
      VECTOR_KEY_B64,
      VECTOR_DEVICE_ID,
      "5R9K6",
      VECTOR_UNIX_SECONDS
    );
    expect(why).toBe("malformed");
  });

  it("reads a code far past the diagnostic window as a mismatch", async () => {
    const ancient = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET - 400);
    const why = await explainEnrollmentFailure(
      VECTOR_KEY_B64,
      VECTOR_DEVICE_ID,
      ancient,
      VECTOR_UNIX_SECONDS
    );
    expect(why).toBe("mismatch");
  });

  // The load-bearing property. The diagnostic exists to CHOOSE COPY, and this
  // pins that widening it never widens the gate: a code it calls "expired" is
  // still one verifyEnrollmentCode refuses.
  it("does not make the gate accept anything it refused", async () => {
    const stale = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET - 6);

    expect(
      await explainEnrollmentFailure(VECTOR_KEY_B64, VECTOR_DEVICE_ID, stale, VECTOR_UNIX_SECONDS)
    ).toBe("expired");
    expect(
      await verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, stale, VECTOR_UNIX_SECONDS)
    ).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npx vitest run src/lib/deviceEnrollment.test.ts`
Expected: FAIL — `explainEnrollmentFailure is not exported by ./deviceEnrollment`.

- [ ] **Step 3: Write the implementation**

Append to `frontend/src/lib/deviceEnrollment.ts` (do not edit anything above it):

```ts
/**
 * How many buckets back the diagnostic looks: 15, or 30 minutes.
 *
 * Long enough to cover a user who started the ceremony and walked away, short
 * enough that the walk stays cheap. This bound is NOT a security parameter —
 * widening it cannot make anything sealable, because nothing downstream of this
 * function seals. See explainEnrollmentFailure.
 */
const DIAGNOSTIC_BUCKETS = 15;

export type EnrollmentFailure = "malformed" | "expired" | "mismatch";

/**
 * Why verifyEnrollmentCode said no — for CHOOSING ERROR COPY, never for deciding.
 *
 * The gate cannot distinguish a stale code from a substituted key: both are
 * simply `false`. But they mean opposite things to the person typing. One says
 * the code timed out and the phone should mint another; the other says the key
 * this server handed over is not the key on that phone. Showing the second
 * message for the first cause teaches users to ignore the only alarm this
 * feature has.
 *
 * CALL THIS ONLY AFTER verifyEnrollmentCode HAS ALREADY REFUSED. It is
 * deliberately a separate function rather than a richer return type on the
 * gate: the gate still accepts the current and previous bucket and nothing
 * else, so no conclusion reached here can widen what gets sealed. A single
 * function that both decided and explained would be one careless edit away from
 * accepting what it was only ever meant to describe.
 */
export async function explainEnrollmentFailure(
  publicKeyB64: string,
  deviceId: string,
  typed: string,
  nowUnixSeconds: number = Math.floor(Date.now() / 1000),
): Promise<EnrollmentFailure> {
  const candidate = normalizeEnrollmentCode(typed);
  if (candidate.length !== CODE_LENGTH) return "malformed";
  for (const ch of candidate) {
    if (!CROCKFORD.includes(ch)) return "malformed";
  }

  // Starts at current-2: the gate already tried the current and previous
  // buckets, so reaching here means neither matched.
  const current = bucketFor(nowUnixSeconds);
  for (let back = 2; back <= DIAGNOSTIC_BUCKETS; back += 1) {
    let expected: string;
    try {
      expected = await deriveEnrollmentCode(publicKeyB64, deviceId, current - back);
    } catch {
      // A key that will not decode cannot have produced this code honestly.
      return "mismatch";
    }
    if (codesEqual(expected, candidate)) return "expired";
  }
  return "mismatch";
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npx vitest run src/lib/deviceEnrollment.test.ts`
Expected: PASS — 25 tests (the original 20 plus 5).

- [ ] **Step 5: Confirm the shipped vector is untouched**

Run: `cd frontend && npx vitest run src/lib/deviceEnrollment.test.ts -t "cross-implementation vector"`
Expected: PASS. If the `5R9K6FWA18` snapshot changed, something above the appended block was edited — revert it. That snapshot is a wire-format break, not a test update.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/lib/deviceEnrollment.ts frontend/src/lib/deviceEnrollment.test.ts
git commit -m "feat(pgp): tell an expired enrollment code from a substituted key"
```

---

### Task 4: The card — device list, indicator, self-gating

The card renders the paired devices and what each one can do. It is deliberately invisible until the mobile half ships: enrollment is offered only for a device that has published a key, and no device has until 2c lands. That is the gate instead of a feature flag.

**Files:**
- Create: `frontend/src/components/DeviceEnrollmentCard.tsx`
- Create: `frontend/src/components/DeviceEnrollmentCard.test.tsx`
- Modify: `frontend/src/pages/SecurityPage.tsx` (import, and render after the PGP card's closing `</div>` at line 1054)

**Interfaces:**
- Consumes: `listNativeDevices`, `type NativeDevice` (Task 1); `toErrorMessage` from `../api/client`.
- Produces: `<DeviceEnrollmentCard fingerprint={string} clientProtected={boolean} unlocked={boolean} onRequestUnlock={() => void} />`. Tasks 5-7 extend this same component.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/components/DeviceEnrollmentCard.test.tsx`:

```tsx
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { DeviceEnrollmentCard } from "./DeviceEnrollmentCard";
import type { NativeDevice } from "../api/devices";

const listNativeDevices = vi.fn();
vi.mock("../api/devices", () => ({ listNativeDevices: () => listNativeDevices() }));
vi.mock("../api/client", () => ({
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

function device(over: Partial<NativeDevice> = {}): NativeDevice {
  return {
    deviceId: "d1",
    platform: "android",
    pushToken: "tok",
    deviceName: "Pixel",
    encryptionEnrolled: false,
    ...over
  };
}

function renderCard(over: Partial<Parameters<typeof DeviceEnrollmentCard>[0]> = {}) {
  return render(
    <DeviceEnrollmentCard
      fingerprint="AAAA1111BBBB2222"
      clientProtected
      unlocked
      onRequestUnlock={() => {}}
      {...over}
    />
  );
}

afterEach(cleanup);

beforeEach(() => {
  listNativeDevices.mockReset();
  listNativeDevices.mockResolvedValue({ devices: [] });
});

describe("DeviceEnrollmentCard", () => {
  it("offers enrollment for a device that has published a key", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: "KEY" })] });
    renderCard();

    expect(await screen.findByText("Pixel")).toBeTruthy();
    expect(await screen.findByRole("button", { name: "Enroll" })).toBeTruthy();
  });

  // Self-gating: until the mobile half ships, every device looks like this, so
  // the card offers nothing rather than a button leading nowhere.
  it("offers nothing for a device that has published no key", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device()] });
    renderCard();

    expect(await screen.findByText("Pixel")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Enroll" })).toBeNull();
  });

  it("shows an enrolled device as able to read encrypted mail", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: "KEY", encryptionEnrolled: true })]
    });
    renderCard();

    expect(await screen.findByText(/can read your encrypted mail/i)).toBeTruthy();
  });

  // Nothing to seal without a client-held key: the PGP card above already
  // tells that story, and repeating it here as a broken affordance is worse.
  it("renders nothing when the account holds no client-protected key", () => {
    const { container } = renderCard({ clientProtected: false });
    expect(container.firstChild).toBeNull();
  });

  // Replacing the identity clears every non-password slot on the server, so a
  // list cached across that change would keep showing devices as able to read
  // mail they can no longer open.
  it("re-reads the list when the identity changes", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: "KEY", encryptionEnrolled: true })]
    });
    const { rerender } = renderCard();
    await screen.findByText("Pixel");
    expect(listNativeDevices).toHaveBeenCalledTimes(1);

    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: "KEY" })] });
    rerender(
      <DeviceEnrollmentCard
        fingerprint="CCCC3333DDDD4444"
        clientProtected
        unlocked
        onRequestUnlock={() => {}}
      />
    );

    await vi.waitFor(() => expect(listNativeDevices).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/not enrolled/i)).toBeTruthy();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx`
Expected: FAIL — `Failed to resolve import "./DeviceEnrollmentCard"`.

- [ ] **Step 3: Write the component**

Create `frontend/src/components/DeviceEnrollmentCard.tsx`:

```tsx
import { useCallback, useEffect, useState } from "react";
import { toErrorMessage } from "../api/client";
import { listNativeDevices, type NativeDevice } from "../api/devices";

/**
 * "Encrypted mail on your devices" — the browser half of device enrollment.
 *
 * A paired phone cannot open the account's PGP envelope, because that envelope
 * is sealed under the account password and pairing never learns it. Enrollment
 * gives the device its own sealing, opened by its secure element.
 *
 * THE SECURITY OF THIS WHOLE FEATURE IS ONE COMPARISON, and it happens here.
 * The server stores and serves the device's public key, so the server is the
 * party that can substitute its own and then open anything sealed to it. The
 * user types a code the device derived from the key in its own keystore; this
 * card derives the same code from the key the server handed over. If they
 * differ, the server substituted, and the ceremony refuses to seal.
 *
 * See docs/superpowers/specs/2026-08-05-device-enrollment-2b-design.md.
 */

export type DeviceEnrollmentCardProps = {
  /** The account's PGP fingerprint. Bound into the envelope's AAD. */
  fingerprint: string;
  /** True when protection is "client" — the only mode with a key to seal. */
  clientProtected: boolean;
  /** Whether the vault is open right now. */
  unlocked: boolean;
  /** Opens the page's existing PgpUnlockDialog. */
  onRequestUnlock: () => void;
};

type EnrollmentState = "unsupported" | "available" | "enrolled";

/**
 * What this device can do, from what it has published.
 *
 * "unsupported" is the pre-2c state and also the permanent state of any client
 * that cannot hold a non-extractable key — it is not an error and must not read
 * as one.
 */
function enrollmentState(device: NativeDevice): EnrollmentState {
  if (!device.enrollmentPublicKey) return "unsupported";
  return device.encryptionEnrolled ? "enrolled" : "available";
}

function deviceLabel(device: NativeDevice): string {
  return device.deviceName?.trim() || device.platform || device.deviceId;
}

export function DeviceEnrollmentCard({
  fingerprint,
  clientProtected,
  unlocked,
  onRequestUnlock
}: DeviceEnrollmentCardProps) {
  const [devices, setDevices] = useState<NativeDevice[]>([]);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const next = await listNativeDevices();
      setDevices(Array.isArray(next.devices) ? next.devices : []);
      setError("");
    } catch (e) {
      // An empty list must not be how a failed fetch presents: that reads as
      // "no devices are enrolled", which is the reassuring answer and may be
      // the wrong one.
      setError(toErrorMessage(e, "Could not read your paired devices."));
    }
  }, []);

  // `fingerprint` is in the deps deliberately. Replacing the identity clears
  // every non-password slot on the server, so every device's enrollment marker
  // becomes false — and a list cached across that change would keep showing
  // devices as able to read mail they can no longer open.
  useEffect(() => {
    if (clientProtected) void refresh();
  }, [clientProtected, fingerprint, refresh]);

  // Nothing to seal, so nothing to offer. The PGP card above this one is where
  // an account without a client-held key gets told about it.
  if (!clientProtected || !fingerprint) return null;

  return (
    <div className="sec-card">
      <div className="sec-card-head">
        <p className="sec-eyebrow">Mail</p>
        <h3>Encrypted mail on your devices</h3>
      </div>
      <p className="sec-muted">
        A paired device cannot read your encrypted mail until you enroll it. Enrolling gives that
        device its own copy of your key, opened by its secure hardware rather than your password.
      </p>
      {error ? <p className="sec-muted">{error}</p> : null}
      {devices.length === 0 ? (
        <p className="sec-muted">
          No paired devices yet. Pair a device on the Notifications page first.
        </p>
      ) : (
        <ul className="sec-devices">
          {devices.map((device) => {
            const state = enrollmentState(device);
            return (
              <li key={device.deviceId}>
                <span className="sec-device-name">{deviceLabel(device)}</span>
                {state === "enrolled" ? (
                  <p className="sec-muted">This device can read your encrypted mail.</p>
                ) : state === "available" ? (
                  <>
                    <p className="sec-muted">Not enrolled. It cannot read your encrypted mail.</p>
                    <button type="button" onClick={() => {}}>
                      Enroll
                    </button>
                  </>
                ) : (
                  <p className="sec-muted">
                    This device's app is too old to be enrolled. Update it and pair again.
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {!unlocked ? (
        <p className="sec-muted">
          <button type="button" onClick={onRequestUnlock}>
            Unlock your key
          </button>{" "}
          before enrolling a device.
        </p>
      ) : null}
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx`
Expected: PASS (5 tests).

- [ ] **Step 5: Mount it on the Security page**

In `frontend/src/pages/SecurityPage.tsx`, add the import next to the other component imports (near line 38):

```ts
import { DeviceEnrollmentCard } from "../components/DeviceEnrollmentCard";
```

Immediately after the PGP card's closing `</div>` (line 1054, before the next `<div className="sec-card"`), insert:

```tsx
        <DeviceEnrollmentCard
          fingerprint={pgpIdentity?.fingerprint ?? ""}
          clientProtected={keyCustody === "client"}
          unlocked={pgpSession?.unlocked ?? false}
          onRequestUnlock={() => setUnlockOpen(true)}
        />
```

- [ ] **Step 6: Verify the page still builds and its tests pass**

Run: `cd frontend && npx tsc --noEmit && npx vitest run`
Expected: tsc clean; whole suite passes.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/DeviceEnrollmentCard.tsx frontend/src/components/DeviceEnrollmentCard.test.tsx frontend/src/pages/SecurityPage.tsx
git commit -m "feat(pgp): show which devices can read encrypted mail"
```

---

### Task 5: The gate

The heart of the feature. Three orderings inside `submit` are load-bearing and each has a test: the key is captured once, the vault check runs first, and the `PUT` is reachable only through a passing comparison.

Note the tests use the **real** `deviceEnrollment` module — no mock — so "a substituted key" means an actually different key producing an actually different code. Mocking the derivation here would test the mock.

**Files:**
- Modify: `frontend/src/components/DeviceEnrollmentCard.tsx`
- Modify: `frontend/src/components/DeviceEnrollmentCard.test.tsx`

**Interfaces:**
- Consumes: `verifyEnrollmentCode`, `sealEnvelopeForDevice`, `formatEnrollmentCode` from `../lib/deviceEnrollment`; `requireUnlockedKey` from `../lib/keyVault`; `putDeviceEnvelope` from `../api/pgp` (Task 2).
- Produces: no new exports. Task 6 extends the same `submit`.

- [ ] **Step 1: Write the failing tests**

Add to the top of `frontend/src/components/DeviceEnrollmentCard.test.tsx`, alongside the existing mocks:

```tsx
import userEvent from "@testing-library/user-event";
import { deriveEnrollmentCode, bucketFor } from "../lib/deviceEnrollment";

const putDeviceEnvelope = vi.fn();
const requireUnlockedKey = vi.fn();

vi.mock("../api/pgp", () => ({
  putDeviceEnvelope: (id: string, envelope: unknown, password: string) =>
    putDeviceEnvelope(id, envelope, password)
}));

vi.mock("../lib/keyVault", () => ({
  requireUnlockedKey: () => requireUnlockedKey()
}));

// deviceEnrollment is NOT mocked away — a test with a mocked derivation tests
// the mock, and "a substituted key" has to mean an actually different key
// producing an actually different code. The seal is wrapped in a spy only so a
// test can see WHICH key bytes reached it, and still runs for real.
const sealSpy = vi.fn();
vi.mock("../lib/deviceEnrollment", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/deviceEnrollment")>();
  return {
    ...actual,
    sealEnvelopeForDevice: (...args: Parameters<typeof actual.sealEnvelopeForDevice>) => {
      sealSpy(...args);
      return actual.sealEnvelopeForDevice(...args);
    }
  };
});

// A real, valid P-256 point, so sealEnvelopeForDevice's ECDH import succeeds.
// Generated once at module load rather than hard-coded, because a fixed point
// would have to be checked by hand against the curve.
const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
  "deriveBits"
]);
const HONEST_KEY = btoa(
  String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey)))
);

const otherPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
  "deriveBits"
]);
const SUBSTITUTED_KEY = btoa(
  String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", otherPair.publicKey)))
);

async function codeFor(publicKeyB64: string, deviceId = "d1"): Promise<string> {
  return deriveEnrollmentCode(publicKeyB64, deviceId, bucketFor(Math.floor(Date.now() / 1000)));
}

async function startCeremony() {
  await userEvent.click(await screen.findByRole("button", { name: "Enroll" }));
}

async function submitCeremony(code: string, password = "hunter2") {
  await userEvent.type(screen.getByLabelText("Code from your device"), code);
  await userEvent.type(screen.getByLabelText("Account password"), password);
  await userEvent.click(screen.getByRole("button", { name: "Verify and enroll" }));
}
```

Extend the `beforeEach` with:

```tsx
  putDeviceEnvelope.mockReset();
  requireUnlockedKey.mockReset();
  sealSpy.mockReset();
  putDeviceEnvelope.mockResolvedValue({ ok: true });
  requireUnlockedKey.mockReturnValue("-----BEGIN PGP PRIVATE KEY BLOCK-----");
```

Then add:

```tsx
describe("the gate", () => {
  // THE test. A hostile server serves its own key; the user types the code
  // their phone actually shows. Assert the ABSENCE of the request, not the
  // presence of a warning — a warning beside a sent request is the failure
  // this whole design exists to prevent.
  it("issues no PUT when the served key is not the device's key", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: SUBSTITUTED_KEY })]
    });
    renderCard();
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(await screen.findByText(/not the key on that device/i)).toBeTruthy();
  });

  it("seals and uploads when the code matches", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    await vi.waitFor(() => expect(putDeviceEnvelope).toHaveBeenCalledTimes(1));
    const [deviceId, envelope, password] = putDeviceEnvelope.mock.calls[0];
    expect(deviceId).toBe("d1");
    expect(password).toBe("hunter2");
    expect(envelope.alg).toBe("ECDH-P256+HKDF-SHA256+A256GCM");
  });

  // The original attack arriving through the back door of a refetch: verify
  // against an honest key, then seal against whatever the list holds now. The
  // ceremony snapshots the key when it opens, so a mid-ceremony refresh cannot
  // change what gets sealed to.
  it("seals to the key it verified, not to a later one", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    // The server flips its answer after the dialog is open.
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: SUBSTITUTED_KEY })]
    });

    await submitCeremony(await codeFor(HONEST_KEY));

    await vi.waitFor(() => expect(putDeviceEnvelope).toHaveBeenCalledTimes(1));
    // The assertion that carries the property: the bytes handed to the seal are
    // the bytes that were verified, not the ones the list holds now.
    expect(sealSpy.mock.calls[0][0]).toBe(HONEST_KEY);
    expect(sealSpy.mock.calls[0][0]).not.toBe(SUBSTITUTED_KEY);
  });

  // A locked vault is mundane. Reporting it as a mismatch would show the most
  // alarming message in the product for the most ordinary cause.
  it("refuses a locked vault without calling it a mismatch", async () => {
    requireUnlockedKey.mockImplementation(() => {
      throw new Error("vault is locked");
    });
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(screen.queryByText(/not the key on that device/i)).toBeNull();
    expect(await screen.findByText(/unlock your key/i)).toBeTruthy();
  });

  // There is no "seal anyway" — the refusal is not click-through-able because
  // there is nothing to click. Stronger than a warning asked to be respected.
  it("offers no way from a refusal to a seal", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: SUBSTITUTED_KEY })]
    });
    renderCard();
    await startCeremony();
    await submitCeremony(await codeFor(HONEST_KEY));

    expect(screen.queryByRole("button", { name: /anyway|continue|proceed|override/i })).toBeNull();
    // The submit button is disabled until the entry actually changes.
    expect(screen.getByRole("button", { name: "Verify and enroll" }).hasAttribute("disabled")).toBe(
      true
    );
    expect(putDeviceEnvelope).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx`
Expected: FAIL — no `Code from your device` field exists; the Enroll button does nothing.

- [ ] **Step 3: Implement the ceremony**

In `frontend/src/components/DeviceEnrollmentCard.tsx`, extend the imports:

```tsx
import { putDeviceEnvelope } from "../api/pgp";
import { requireUnlockedKey } from "../lib/keyVault";
import { sealEnvelopeForDevice, verifyEnrollmentCode } from "../lib/deviceEnrollment";
```

Add above the component:

```tsx
/**
 * One run of the ceremony.
 *
 * `publicKey` is snapshotted here rather than read from the device list at seal
 * time, and that is not a convenience. Verifying against one fetch and sealing
 * against another would let a server answer honestly once and hostilely once —
 * the comparison passes on bytes that are never sealed to, which is the exact
 * attack the comparison exists to catch, arriving through a refetch.
 */
type Ceremony = {
  device: NativeDevice;
  publicKey: string;
};
```

Add inside the component, after the existing state:

```tsx
  const [ceremony, setCeremony] = useState<Ceremony | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [failure, setFailure] = useState("");
  const [busy, setBusy] = useState(false);

  function openCeremony(device: NativeDevice) {
    setCeremony({ device, publicKey: device.enrollmentPublicKey ?? "" });
    setCode("");
    setPassword("");
    setFailure("");
  }

  async function submit() {
    if (!ceremony || busy) return;
    setBusy(true);
    setFailure("");
    try {
      // FIRST, before anything derives: a locked vault is an ordinary state and
      // must not surface as the substituted-key alarm.
      let armored: string;
      try {
        armored = requireUnlockedKey();
      } catch {
        setFailure("locked");
        return;
      }

      const { device, publicKey } = ceremony;

      // THE GATE. Everything below it is unreachable without a match.
      if (!(await verifyEnrollmentCode(publicKey, device.deviceId, code))) {
        setFailure("mismatch");
        return;
      }

      const envelope = await sealEnvelopeForDevice(publicKey, device.deviceId, fingerprint, armored);
      await putDeviceEnvelope(device.deviceId, envelope, password);
      setCeremony(null);
      await refresh();
    } catch (e) {
      setFailure(toErrorMessage(e, "Could not store the sealing."));
    } finally {
      setBusy(false);
    }
  }
```

Wire the Enroll button to `openCeremony(device)`, replacing `onClick={() => {}}`:

```tsx
                    <button type="button" onClick={() => openCeremony(device)}>
                      Enroll
                    </button>
```

Add the dialog immediately before the closing `</div>` of the card:

```tsx
      {ceremony ? (
        <div className="sec-modal">
          <h4>Enroll {deviceLabel(ceremony.device)}</h4>
          <p className="sec-muted">
            Start enrollment on that device and type the ten-character code it shows. The code is
            good for two to four minutes depending on when the device generated it.
          </p>
          <label>
            Code from your device
            <input
              value={code}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => {
                setCode(e.target.value);
                // Clearing the refusal on edit is what makes it
                // non-click-through-able: the only way past a mismatch is to
                // type something different.
                setFailure("");
              }}
            />
          </label>
          <label>
            Account password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {failure === "locked" ? (
            <p className="sec-muted">
              Unlock your key before enrolling this device. Nothing was sent.
            </p>
          ) : failure === "mismatch" ? (
            <p className="sec-warn">
              That code does not match. The key this server gave the browser is not the key on that
              device — so your key was NOT sent to it. Do not try again on this server without
              checking with whoever runs it.
            </p>
          ) : failure ? (
            <p className="sec-warn">{failure}</p>
          ) : null}
          <button type="button" disabled={busy || !!failure} onClick={() => void submit()}>
            Verify and enroll
          </button>
          <button type="button" disabled={busy} onClick={() => setCeremony(null)}>
            Cancel
          </button>
        </div>
      ) : null}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx`
Expected: PASS (10 tests).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/DeviceEnrollmentCard.tsx frontend/src/components/DeviceEnrollmentCard.test.tsx
git commit -m "feat(pgp): gate the device sealing on the typed code"
```

---

### Task 6: The failure taxonomy

Six outcomes, six messages. A malformed entry is not a mismatch and must not consume an attempt; an expired code is not alarming and must not read as one; three attempts end the ceremony, because typing ten characters invites a real typo while blind guessing is hopeless.

**Files:**
- Modify: `frontend/src/components/DeviceEnrollmentCard.tsx`
- Modify: `frontend/src/components/DeviceEnrollmentCard.test.tsx`

**Interfaces:**
- Consumes: `explainEnrollmentFailure`, `type EnrollmentFailure` from `../lib/deviceEnrollment` (Task 3).
- Produces: no new exports.

- [ ] **Step 1: Write the failing tests**

Add to `frontend/src/components/DeviceEnrollmentCard.test.tsx`:

```tsx
describe("the failure taxonomy", () => {
  it("reports an expired code as expiry, not as a substituted key", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    const stale = await deriveEnrollmentCode(
      HONEST_KEY,
      "d1",
      bucketFor(Math.floor(Date.now() / 1000)) - 5
    );
    await submitCeremony(stale);

    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(await screen.findByText(/expired/i)).toBeTruthy();
    expect(screen.queryByText(/not the key on that device/i)).toBeNull();
  });

  it("names a short entry as incomplete rather than as a mismatch", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    await submitCeremony("5R9K6");

    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(await screen.findByText(/ten characters/i)).toBeTruthy();
    expect(screen.queryByText(/not the key on that device/i)).toBeNull();
  });

  // Three, not one. The MFA control allows a single attempt because guessing
  // is cheap there; here guessing fifty bits is hopeless and typos are not.
  it("aborts the ceremony after three real attempts", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: SUBSTITUTED_KEY })]
    });
    renderCard();
    await startCeremony();

    for (let i = 0; i < 3; i += 1) {
      const field = screen.getByLabelText("Code from your device");
      await userEvent.clear(field);
      await userEvent.type(field, await codeFor(HONEST_KEY));
      if (i === 0) await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
      const submit = screen.queryByRole("button", { name: "Verify and enroll" });
      if (submit) await userEvent.click(submit);
    }

    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(await screen.findByText(/start enrollment again on the device/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Verify and enroll" })).toBeNull();
  });

  // A malformed entry is the user's finger, not the server's key. Spending an
  // attempt on it would end the ceremony over three typos.
  it("does not spend an attempt on a malformed entry", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    for (let i = 0; i < 4; i += 1) {
      const field = screen.getByLabelText("Code from your device");
      await userEvent.clear(field);
      await userEvent.type(field, "5R9K6");
      if (i === 0) await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
      await userEvent.click(screen.getByRole("button", { name: "Verify and enroll" }));
    }

    expect(screen.queryByText(/start enrollment again on the device/i)).toBeNull();
    expect(screen.getByRole("button", { name: "Verify and enroll" })).toBeTruthy();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx`
Expected: FAIL — every refusal currently renders the mismatch copy.

- [ ] **Step 3: Implement the taxonomy**

In `frontend/src/components/DeviceEnrollmentCard.tsx`, extend the deviceEnrollment import:

```tsx
import {
  explainEnrollmentFailure,
  sealEnvelopeForDevice,
  verifyEnrollmentCode
} from "../lib/deviceEnrollment";
```

Add the attempt counter to the state and reset it in `openCeremony`:

```tsx
  const [attempts, setAttempts] = useState(0);
```

```tsx
    setAttempts(0);
```

Replace the gate block inside `submit` with:

```tsx
      // THE GATE. Everything below it is unreachable without a match.
      if (!(await verifyEnrollmentCode(publicKey, device.deviceId, code))) {
        // Strictly downstream of the refusal: this only chooses which message
        // to show. Nothing past this point seals, so what it concludes cannot
        // widen what the gate accepted.
        const why = await explainEnrollmentFailure(publicKey, device.deviceId, code);
        // A malformed entry is a finger, not a server. Spending an attempt on
        // it would end the ceremony over three typos.
        if (why !== "malformed") setAttempts((n) => n + 1);
        setFailure(why);
        return;
      }
```

Replace the failure-message block in the dialog with:

```tsx
          {failure === "locked" ? (
            <p className="sec-muted">
              Unlock your key before enrolling this device. Nothing was sent.
            </p>
          ) : failure === "malformed" ? (
            <p className="sec-muted">
              The code is ten characters, shown as XXXXX-XXXXX. Type all of it.
            </p>
          ) : failure === "expired" ? (
            <p className="sec-muted">
              That code has expired. Ask the device for a fresh one and type it. If this keeps
              happening, check that the device's clock is correct — a clock running fast fails every
              time.
            </p>
          ) : failure === "mismatch" ? (
            <p className="sec-warn">
              That code does not match. The key this server gave the browser is not the key on that
              device — so your key was NOT sent to it. Do not try again on this server without
              checking with whoever runs it.
            </p>
          ) : failure ? (
            <p className="sec-warn">{failure}</p>
          ) : null}
```

Replace the submit button with an abort-aware version:

```tsx
          {attempts >= 3 ? (
            <p className="sec-warn">
              Too many failed attempts. Start enrollment again on the device to get a new code.
            </p>
          ) : (
            <button type="button" disabled={busy || !!failure} onClick={() => void submit()}>
              Verify and enroll
            </button>
          )}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx`
Expected: PASS (14 tests).

- [ ] **Step 5: Confirm the gate tests still hold**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx -t "the gate"`
Expected: PASS (5 tests). If "issues no PUT" broke, the taxonomy was wired above the gate instead of below it.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/DeviceEnrollmentCard.tsx frontend/src/components/DeviceEnrollmentCard.test.tsx
git commit -m "feat(pgp): say which enrollment failure this is"
```

---

### Task 7: Revocation that does not overpromise

Deleting `device:<id>` removes the server's copy. It does not reach the copy the device re-sealed under its own keystore key, because the server has no reach into that. The copy must say so — a "remove device" that reads as revocation, when the phone still holds a working key, is worse than no button.

**Files:**
- Modify: `frontend/src/components/DeviceEnrollmentCard.tsx`
- Modify: `frontend/src/components/DeviceEnrollmentCard.test.tsx`
- Modify: `docs/superpowers/plans/2026-08-05-device-enrollment-2b-handoff.md` (mark 2b done)

**Interfaces:**
- Consumes: `deleteDeviceEnvelope` from `../api/pgp` (Task 2).
- Produces: nothing further. This completes 2b.

- [ ] **Step 1: Write the failing tests**

Add to `frontend/src/components/DeviceEnrollmentCard.test.tsx` — and add `deleteDeviceEnvelope` to the `../api/pgp` mock factory and the `beforeEach` resets:

```tsx
const deleteDeviceEnvelope = vi.fn();
```

```tsx
vi.mock("../api/pgp", () => ({
  putDeviceEnvelope: (id: string, envelope: unknown, password: string) =>
    putDeviceEnvelope(id, envelope, password),
  deleteDeviceEnvelope: (id: string, password: string) => deleteDeviceEnvelope(id, password)
}));
```

```tsx
  deleteDeviceEnvelope.mockReset();
  deleteDeviceEnvelope.mockResolvedValue({ ok: true });
```

```tsx
describe("revocation", () => {
  // The honest sentence. Without it "remove" reads as revocation, and the user
  // walks away believing a phone they no longer control cannot read their mail.
  it("says removal does not reach what the device already holds", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: HONEST_KEY, encryptionEnrolled: true })]
    });
    renderCard();

    await userEvent.click(await screen.findByRole("button", { name: "Remove sealing" }));

    expect(await screen.findByText(/does not erase the copy that device already has/i)).toBeTruthy();
    expect(await screen.findByText(/replace your key/i)).toBeTruthy();
  });

  it("removes the server's copy with the account credential", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: HONEST_KEY, encryptionEnrolled: true })]
    });
    renderCard();
    await userEvent.click(await screen.findByRole("button", { name: "Remove sealing" }));

    await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Remove it" }));

    await vi.waitFor(() => expect(deleteDeviceEnvelope).toHaveBeenCalledWith("d1", "hunter2"));
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx`
Expected: FAIL — no `Remove sealing` button exists.

- [ ] **Step 3: Implement removal**

In `frontend/src/components/DeviceEnrollmentCard.tsx`, extend the pgp import:

```tsx
import { deleteDeviceEnvelope, putDeviceEnvelope } from "../api/pgp";
```

Add state and the handler:

```tsx
  const [removing, setRemoving] = useState<NativeDevice | null>(null);
  const [removePassword, setRemovePassword] = useState("");

  async function removeSealing() {
    if (!removing || busy) return;
    setBusy(true);
    try {
      await deleteDeviceEnvelope(removing.deviceId, removePassword);
      setRemoving(null);
      setRemovePassword("");
      await refresh();
    } catch (e) {
      setError(toErrorMessage(e, "Could not remove the sealing."));
    } finally {
      setBusy(false);
    }
  }
```

Add the button to the `enrolled` branch of the list:

```tsx
                {state === "enrolled" ? (
                  <>
                    <p className="sec-muted">This device can read your encrypted mail.</p>
                    <button type="button" onClick={() => setRemoving(device)}>
                      Remove sealing
                    </button>
                  </>
                ) : state === "available" ? (
```

Add the confirmation before the card's closing `</div>`:

```tsx
      {removing ? (
        <div className="sec-modal">
          <h4>Remove {deviceLabel(removing)}'s sealing</h4>
          <p className="sec-warn">
            This removes the copy on the server. It does not erase the copy that device already has
            — once a device has taken its sealing, it keeps working offline and the server cannot
            reach it.
          </p>
          <p className="sec-muted">
            To actually stop a device you no longer control from reading new mail, replace your key
            in the section above. That invalidates every device's sealing, and each one you still
            use has to enroll again.
          </p>
          <label>
            Account password
            <input
              type="password"
              value={removePassword}
              onChange={(e) => setRemovePassword(e.target.value)}
            />
          </label>
          <button type="button" disabled={busy} onClick={() => void removeSealing()}>
            Remove it
          </button>
          <button type="button" disabled={busy} onClick={() => setRemoving(null)}>
            Cancel
          </button>
        </div>
      ) : null}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx vitest run src/components/DeviceEnrollmentCard.test.tsx`
Expected: PASS (16 tests).

- [ ] **Step 5: Run every gate before claiming 2b is done**

Run: `cd frontend && npx tsc --noEmit && npx vitest run && npx vite build`
Expected: tsc clean, whole suite green, build succeeds. Do not proceed on a partial pass.

- [ ] **Step 6: Close the handoff**

In `docs/superpowers/plans/2026-08-05-device-enrollment-2b-handoff.md`, replace the entire "## What is left" section (its heading and all three numbered items) with exactly:

```markdown
## Shipped

All three are done. See
`docs/superpowers/specs/2026-08-05-device-enrollment-2b-design.md` for the decisions.

1. **The envelope API client** — `putDeviceEnvelope` / `deleteDeviceEnvelope` in
   `src/api/pgp.ts`. No `GET`: the browser writes, the device reads its own.
2. **The Security page UI** — `src/components/DeviceEnrollmentCard.tsx`. The device-list
   fork resolved toward a new card sharing `src/api/devices.ts` as a typed fetch, not a
   shared render component. One device still appears in three lists; a Devices page is
   the recorded fix and waits for 2c.
3. **Revocation copy** — states that removal does not reach what the device already holds,
   and points at replacing the identity as the real revocation.

**Nothing is user-visible yet.** Enrollment is offered only for a device whose
`enrollmentPublicKey` is non-empty, which is no device until 2c publishes one. That is the
gate instead of a feature flag.
```

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/DeviceEnrollmentCard.tsx frontend/src/components/DeviceEnrollmentCard.test.tsx
git add -f docs/superpowers/plans/2026-08-05-device-enrollment-2b-handoff.md
git commit -m "feat(pgp): remove a device sealing without overpromising"
```

---

## Verification checklist

Every item is a claim this plan makes; none may be asserted without running the command.

- [ ] `cd frontend && npx tsc --noEmit` — clean.
- [ ] `cd frontend && npx vitest run` — whole suite green.
- [ ] `cd frontend && npx vite build` — succeeds.
- [ ] `npx vitest run src/lib/deviceEnrollment.test.ts -t "cross-implementation vector"` — `5R9K6FWA18` unchanged.
- [ ] `git log --oneline` shows seven task commits.

## Out of scope

- **2c (Android) and 2d (Qt).** Nothing here is user-visible until a device publishes an enrollment key.
- **A browser `GET` client for envelope slots.** The device reads its own; the browser writes.
- **A rotate-and-re-enroll wizard.** Rotation already invalidates every sealing.
- **The Devices page.** Recorded as deferred in the design doc; `src/api/devices.ts` is the seam it consumes.
